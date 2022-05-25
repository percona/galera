/* Copyright 2010-2015 Codership Oy <http://www.codership.com>

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; version 2 of the License.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

//! @file some utility functions and classes not directly related to replication

#ifndef _GNU_SOURCE
#define _GNU_SOURCE  // POSIX_SPAWN_USEVFORK flag
#endif

#include "process.h"
#include <errno.h>   // errno
#include <netdb.h>   // getaddrinfo()
#include <signal.h>  // sigemptyset(), sigaddset()
#include <signal.h>
#include <string.h>  // strerror()
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/wait.h>  // waitpid()
#include <unistd.h>    // pipe()

#define PIPE_READ 0
#define PIPE_WRITE 1
#define STDIN_FD 0
#define STDOUT_FD 1
#define STDERR_FD 2

#define WSREP_ERROR printf
#define WSREP_WARN printf

process::process(const char *cmd, const char *type, char **env,
                 bool execute_immediately)
    : str_(cmd ? strdup(cmd) : strdup("")),
      io_(NULL),
      io_w_(NULL),
      io_err_(NULL),
      err_(0),
      pid_(0) {
  if (execute_immediately) execute(type, env);
}

void process::execute(const char *type, char **env) {
  int sig;
  struct sigaction sa;

  if (0 == str_) {
    WSREP_ERROR("Can't allocate command line.");
    err_ = ENOMEM;
    return;
  }

  if (0 == strlen(str_)) {
    WSREP_ERROR("Can't start a process: null or empty command line.");
    return;
  }

  if (NULL == type ||
      (strcmp(type, "w") && strcmp(type, "r") && strcmp(type, "rw"))) {
    WSREP_ERROR("type argument should be either \"r\" or \"w\" or \"rw\".");
    return;
  }

  if (NULL == env) {
    env = environ;
  }  // default to global environment

  int pipe_fds[2] = {-1, -1};
  int pipe2_fds[2] = {-1, -1};
  int pipeerr_fds[2] = {-1, -1};

  if (::pipe(pipe_fds)) {
    err_ = errno;
    WSREP_ERROR("pipe() failed: %d (%s)", err_, strerror(err_));
    return;
  }

  // which end of pipe will be returned to parent
  int const parent_end(strcmp(type, "w") ? PIPE_READ : PIPE_WRITE);
  int const child_end(parent_end == PIPE_READ ? PIPE_WRITE : PIPE_READ);
  int const close_fd(parent_end == PIPE_READ ? STDOUT_FD : STDIN_FD);

  char *const pargv[4] = {strdup("bash"), strdup("-c"), strdup(str_), NULL};

  // Create the second pipe (needed only if type = "rw")
  // One pipe for reading and one pipe for writing
  if (strcmp(type, "rw") == 0 && ::pipe(pipe2_fds)) {
    err_ = errno;
    WSREP_ERROR("pipe() failed to create the second pipe: %d (%s)", err_,
                strerror(err_));
    goto cleanup_pipe;
  }

  if (::pipe(pipeerr_fds)) {
    err_ = errno;
    WSREP_ERROR("pipe() failed to create the error pipe: %d (%s)", err_,
                strerror(err_));
    goto cleanup_pipe;
  }

  if (!(pargv[0] && pargv[1] && pargv[2])) {
    err_ = ENOMEM;
    WSREP_ERROR("Failed to allocate pargv[] array.");
    goto cleanup_pipe;
  }

#ifndef _POSIX_SPAWN

  pid_ = fork();

  if (pid_ == -1) {
    err_ = errno;
    WSREP_ERROR("fork() failed: %d (%s)", err_, strerror(err_));
    pid_ = 0;
    goto cleanup_pipe;
  } else if (pid_ > 0) {
    /* Parent */

    // Treat 'rw' as an 'r'
    io_ = fdopen(pipe_fds[parent_end], (strcmp(type, "rw") == 0 ? "r" : type));

    if (io_) {
      pipe_fds[parent_end] = -1;  // skip close on cleanup
    } else {
      err_ = errno;
      WSREP_ERROR("fdopen() failed: %d (%s)", err_, strerror(err_));
    }

    if (strcmp(type, "rw") == 0) {
      // Need to open the write end of the pipe
      io_w_ = fdopen(pipe2_fds[PIPE_WRITE], "w");
      if (io_w_) {
        pipe2_fds[PIPE_WRITE] = -1;  // skip close on cleanup
      } else {
        err_ = errno;
        WSREP_ERROR("fdopen() failed: %d (%s)", err_, strerror(err_));
      }
    }

    io_err_ = fdopen(pipeerr_fds[PIPE_READ], "r");
    if (io_err_) {
      pipeerr_fds[PIPE_READ] = -1;  // skip close on cleanup
    } else {
      err = errno;
      WSREP_ERROR("fdopen() failed: %d (%s)", err_, strerror(err_));
    }

    goto cleanup_pipe;
  }

  /* Child */

#ifdef PR_SET_PDEATHSIG
  /*
    Ensure this process gets SIGTERM when the server is terminated for
    whatever reasons.
  */

  if (prctl(PR_SET_PDEATHSIG, SIGTERM)) {
    WSREP_ERROR("prctl() failed");
    _exit(EXIT_FAILURE);
  }
#endif

  /* Reset the process signal mask to unblock signals blocked by the server */

  sigset_t set;
  (void)sigemptyset(&set);

  if (sigprocmask(SIG_SETMASK, &set, NULL)) {
    WSREP_ERROR("sigprocmask() failed");
    _exit(EXIT_FAILURE);
  }

  /* Reset all ignored signals to SIG_DFL */

  memset(&sa, 0, sizeof(sa));
  sa.sa_handler = SIG_DFL;

  for (sig = 1; sig < NSIG; sig++) {
    /*
      For some signals sigaction() even when SIG_DFL handler is set, so don't
      check for return value here.
    */
    sigaction(sig, &sa, NULL);
  }

  /*
    Make the child process a session/group leader. This is required to
    simplify cleanup procedure for SST process, so that all processes spawned
    by the SST script could be killed by killing the entire process group.
  */

  if (setsid() < 0) {
    WSREP_ERROR("setsid() failed");
    _exit(EXIT_FAILURE);
  }

  /* Close child's stdout|stdin depending on what we returning.    */
  /* PXC-502: commented out, because subsequent dup2() call closes */
  /* close_fd descriptor automatically.                            */
  /*
  if (close(close_fd) < 0)
  {
    sql_print_error("close() failed");
    _exit(EXIT_FAILURE);
  }
  */

  /* substitute our pipe descriptor in place of the closed one */

  if (dup2(pipe_fds[child_end], close_fd) < 0) {
    WSREP_ERROR("dup2() failed");
    _exit(EXIT_FAILURE);
  }
  if ((strcmp(type, "rw") == 0) && dup2(pipe2_fds[PIPE_READ], STDIN_FD) < 0) {
    WSREP_ERROR("dup2() failed");
    _exit(EXIT_FAILURE);
  }
  if (dup2(pipeerr_fds[PIPE_WRITE], STDERR_FD) < 0) {
    WSREP_ERROR("dup2() failed");
    _exit(EXIT_FAILURE);
  }

  /* Close child and parent pipe descriptors after redirection. */

  if (close(pipe_fds[child_end]) < 0) {
    WSREP_ERROR("close() failed");
    _exit(EXIT_FAILURE);
  }

  if (close(pipe_fds[parent_end]) < 0) {
    WSREP_ERROR("close() failed");
    _exit(EXIT_FAILURE);
  }

  if (close(pipe2_fds[child_end]) < 0) {
    WSREP_ERROR("close() failed");
    _exit(EXIT_FAILURE);
  }

  if (close(pipe2_fds[parent_end]) < 0) {
    WSREP_ERROR("close() failed");
    _exit(EXIT_FAILURE);
  }

  if (close(pipeerr_fds[PIPE_WRITE]) < 0) {
    WSREP_ERROR("close() failed");
    _exit(EXIT_FAILURE);
  }

  if (close(pipeerr_fds[PIPE_READ]) < 0) {
    WSREP_ERROR("close() failed");
    _exit(EXIT_FAILURE);
  }

  execvpe(pargv[0], pargv, env);

  WSREP_ERROR("execlp() failed");
  _exit(EXIT_FAILURE);

#else  // _POSIX_SPAWN is defined:

  posix_spawnattr_t sattr;

  err_ = posix_spawnattr_init(&sattr);
  if (err_) {
    WSREP_ERROR("posix_spawnattr_init() failed: %d (%s)", err_, strerror(err_));
    goto cleanup_pipe;
  }

  /*
    Make the child process a session/group leader. This is required to
    simplify cleanup procedure for SST process, so that all processes spawned
    by the SST script could be killed by killing the entire process group:
  */

  err_ = posix_spawnattr_setpgroup(&sattr, 0);
  if (err_) {
    WSREP_ERROR("posix_spawnattr_setpgroup() failed: %d (%s)", err_,
                strerror(err_));
    goto cleanup_attr;
  }

  /* Reset the process signal mask to unblock signals blocked by the server: */

  sigset_t set;

  err_ = sigemptyset(&set);
  if (err_) {
    err_ = errno;
    WSREP_ERROR("sigemptyset() failed: %d (%s)", err_, strerror(err_));
    goto cleanup_attr;
  }

  err_ = posix_spawnattr_setsigmask(&sattr, &set);
  if (err_) {
    WSREP_ERROR("posix_spawnattr_setsigmask() failed: %d (%s)", err_,
                strerror(err_));
    goto cleanup_attr;
  }

  /* Reset all ignored signals to SIG_DFL: */

  int def_flag;

  def_flag = 0;

  for (sig = 1; sig < NSIG; sig++) {
    if (sigaction(sig, NULL, &sa) == 0) {
      if (sa.sa_handler == SIG_IGN) {
        err_ = sigaddset(&set, sig);
        if (err_) {
          err_ = errno;
          WSREP_ERROR("sigaddset() failed: %d (%s)", err_, strerror(err_));
          goto cleanup_attr;
        }
        def_flag = POSIX_SPAWN_SETSIGDEF;
      }
    }
  }

  if (def_flag) {
    err_ = posix_spawnattr_setsigdefault(&sattr, &set);
    if (err_) {
      WSREP_ERROR("posix_spawnattr_setsigdefault() failed: %d (%s)", err_,
                  strerror(err_));
      goto cleanup_attr;
    }
  }

  /* Set flags for all modified parameters: */

#ifdef POSIX_SPAWN_USEVFORK
  def_flag |= POSIX_SPAWN_USEVFORK;
#endif

  err_ = posix_spawnattr_setflags(
      &sattr, POSIX_SPAWN_SETPGROUP | POSIX_SPAWN_SETSIGMASK | def_flag);
  if (err_) {
    WSREP_ERROR("posix_spawnattr_setflags() failed: %d (%s)", err_,
                strerror(err_));
    goto cleanup_attr;
  }

  /* Substitute our pipe descriptor in place of the stdin or stdout: */

  posix_spawn_file_actions_t sfa;

  err_ = posix_spawn_file_actions_init(&sfa);
  if (err_) {
    WSREP_ERROR("posix_spawn_file_actions_init() failed: %d (%s)", err_,
                strerror(err_));
    goto cleanup_attr;
  }

  err_ = posix_spawn_file_actions_adddup2(&sfa, pipe_fds[child_end], close_fd);
  if (err_) {
    WSREP_ERROR("posix_spawn_file_actions_adddup2() failed: %d (%s)", err_,
                strerror(err_));
    goto cleanup_actions;
  }

  err_ = posix_spawn_file_actions_addclose(&sfa, pipe_fds[child_end]);
  if (err_) {
    WSREP_ERROR("posix_spawn_file_actions_addclose() failed: %d (%s)", err_,
                strerror(err_));
    goto cleanup_actions;
  }

  err_ = posix_spawn_file_actions_addclose(&sfa, pipe_fds[parent_end]);
  if (err_) {
    WSREP_ERROR("posix_spawn_file_actions_addclose() failed: %d (%s)", err_,
                strerror(err_));
    goto cleanup_actions;
  }

  if (strcmp(type, "rw") == 0) {
    err_ =
        posix_spawn_file_actions_adddup2(&sfa, pipe2_fds[PIPE_READ], STDIN_FD);
    if (err_) {
      WSREP_ERROR("posix_spawn_file_actions_adddup2() failed: %d (%s)", err_,
                  strerror(err_));
      goto cleanup_actions;
    }

    err_ = posix_spawn_file_actions_addclose(&sfa, pipe2_fds[PIPE_READ]);
    if (err_) {
      WSREP_ERROR("posix_spawn_file_actions_addclose() failed: %d (%s)", err_,
                  strerror(err_));
      goto cleanup_actions;
    }

    err_ = posix_spawn_file_actions_addclose(&sfa, pipe2_fds[PIPE_WRITE]);
    if (err_) {
      WSREP_ERROR("posix_spawn_file_actions_addclose() failed: %d (%s)", err_,
                  strerror(err_));
      goto cleanup_actions;
    }
  }

  err_ = posix_spawn_file_actions_adddup2(&sfa, pipeerr_fds[PIPE_WRITE],
                                          STDERR_FD);
  if (err_) {
    WSREP_ERROR("posix_spawn_file_actions_adddup2() failed: %d (%s)", err_,
                strerror(err_));
    goto cleanup_actions;
  }

  err_ = posix_spawn_file_actions_addclose(&sfa, pipeerr_fds[PIPE_WRITE]);
  if (err_) {
    WSREP_ERROR("posix_spawn_file_actions_addclose() failed: %d (%s)", err_,
                strerror(err_));
    goto cleanup_actions;
  }

  err_ = posix_spawn_file_actions_addclose(&sfa, pipeerr_fds[PIPE_READ]);
  if (err_) {
    WSREP_ERROR("posix_spawn_file_actions_addclose() failed: %d (%s)", err_,
                strerror(err_));
    goto cleanup_actions;
  }

  /* Launch the child process: */

  err_ = posix_spawnp(&pid_, pargv[0], &sfa, &sattr, pargv, env);
  if (err_) {
    WSREP_ERROR("posix_spawnp() failed: %d (%s)", err_, strerror(err_));
    pid_ = 0;
    goto cleanup_actions;
  }

  err_ = posix_spawn_file_actions_destroy(&sfa);
  if (err_) {
    WSREP_ERROR("posix_spawn_file_actions_destroy() failed: %d (%s)", err_,
                strerror(err_));
    goto cleanup_attr;
  }

  err_ = posix_spawnattr_destroy(&sattr);
  if (err_) {
    WSREP_ERROR("posix_spawnattr_destroy() failed: %d (%s)", err_,
                strerror(err_));
    goto cleanup_pipe;
  }

  /* We are in the parent process: */

  io_ = fdopen(pipe_fds[parent_end], (strcmp(type, "rw") == 0 ? "r" : type));

  if (io_) {
    pipe_fds[parent_end] = -1;  // skip close on cleanup
  } else {
    err_ = errno;
    WSREP_ERROR("fdopen() failed: %d (%s)", err_, strerror(err_));
  }

  if (strcmp(type, "rw") == 0) {
    io_w_ = fdopen(pipe2_fds[PIPE_WRITE], "w");

    if (io_w_) {
      pipe2_fds[PIPE_WRITE] = -1;  // skip close on cleanup
    } else {
      err_ = errno;
      WSREP_ERROR("fdopen() failed: %d (%s)", err_, strerror(err_));
    }
  }

  io_err_ = fdopen(pipeerr_fds[PIPE_READ], "r");

  if (io_err_) {
    pipeerr_fds[PIPE_READ] = -1;  // skip close on cleanup
  } else {
    err_ = errno;
    WSREP_ERROR("fdopen() failed: %d (%s)", err_, strerror(err_));
  }

#endif

cleanup_pipe:
  if (pipe_fds[0] >= 0) close(pipe_fds[0]);
  if (pipe_fds[1] >= 0) close(pipe_fds[1]);
  if (pipe2_fds[0] >= 0) close(pipe2_fds[0]);
  if (pipe2_fds[1] >= 0) close(pipe2_fds[1]);
  if (pipeerr_fds[0] >= 0) close(pipeerr_fds[0]);
  if (pipeerr_fds[1] >= 0) close(pipeerr_fds[1]);

  free(pargv[0]);
  free(pargv[1]);
  free(pargv[2]);

#ifdef _POSIX_SPAWN
  return;

cleanup_actions:
  posix_spawn_file_actions_destroy(&sfa);

cleanup_attr:
  posix_spawnattr_destroy(&sattr);
  goto cleanup_pipe;

#endif
}

process::~process() {
  //terminate();

  if (io_) {
    assert(pid_);
    assert(str_);
    if (fclose(io_) == -1) {
      err_ = errno;
      WSREP_ERROR("fclose() failed: %d (%s)", err_, strerror(err_));
    }
  }

  if (io_w_) {
    assert(pid_);
    assert(str_);
    if (fclose(io_w_) == -1) {
      err_ = errno;
      WSREP_ERROR("fclose() failed: %d (%s)", err_, strerror(err_));
    }
  }

  if (io_err_) {
    if (fclose(io_err_) == -1) {
      err_ = errno;
      WSREP_ERROR("fclose() failed: %d (%s)", err_, strerror(err_));
    }
  }

  if (str_) free(const_cast<char *>(str_));
}

void process::close_write_pipe() {
  if (io_w_) {
    assert(pid_);
    assert(str_);

    if (fclose(io_w_) == -1) {
      err_ = errno;
      WSREP_ERROR("fclose() failed: %d (%s)", err_, strerror(err_));
    }
    io_w_ = NULL;
  }
}

int process::wait() {
  if (pid_) {
    int status;
    if (-1 == waitpid(pid_, &status, 0)) {
      err_ = errno;
      assert(err_);
      WSREP_ERROR("Waiting for process failed: %s, PID(%ld): %d (%s)", str_,
                  (long)pid_, err_, strerror(err_));
    } else {  // command completed, check exit status
      if (WIFEXITED(status)) {
        err_ = WEXITSTATUS(status);
      } else {  // command didn't complete with exit()
        WSREP_ERROR("Process was aborted.");
        err_ = errno ? errno : ECHILD;
      }

      if (err_) {
        switch (err_) /* Translate error codes to more meaningful */
        {
          case 126:
            err_ = EACCES;
            break; /* Permission denied */
          case 127:
            err_ = ENOENT;
            break; /* No such file or directory */
          case 143:
            err_ = EINTR;
            break; /* Subprocess killed */
        }
        WSREP_ERROR("Process completed with error: %s: %d (%s)", str_, err_,
                    strerror(err_));
      }

      pid_ = 0;
      if (io_) fclose(io_);
      io_ = NULL;
      if (io_w_) fclose(io_w_);
      io_w_ = NULL;
      if (io_err_) fclose(io_err_);
      io_err_ = NULL;
    }
  } else {
    assert(NULL == io_);
    WSREP_ERROR("Command did not run: %s", str_);
  }

  return err_;
}

void process::interrupt() {
  if (pid_) {
    if (kill(pid_, SIGINT))
    {
      WSREP_WARN("Unable to interrupt process: %s: %d (%s)", str_, errno,
                 strerror(errno));
    }
  }
}

void process::terminate() {
  WSREP_WARN("Terminating process");
  if (pid_) {
    /*
      If we have an appropriated system call, then we try
      to terminate entire process group:
    */
#if _XOPEN_SOURCE >= 500 || _DEFAULT_SOURCE || _BSD_SOURCE
    if (killpg(pid_, SIGTERM))
#else
    if (kill(pid_, SIGTERM))
#endif
    {
      WSREP_WARN("Unable to terminate process: %s: %d (%s)", str_, errno,
                 strerror(errno));
    }
  }
}
