/* Copyright (C) 2011-2024 Codership Oy <info@codership.com> */

#include "garb_config.hpp"
#include "garb_recv_loop.hpp"

#include <gu_throw.hpp>

#include <iostream>

#include <stdlib.h> // exit()
#include <unistd.h> // setsid(), chdir()
#include <fcntl.h>  // open()
#include <signal.h>

#if defined(WITH_COREDUMPER) && WITH_COREDUMPER
#include "coredumper/coredumper.h"

/**
   Copies strlen(src) characters of source to destination.
   If strlen(src) is equal or bigger than num then dst will be truncated.
   The null-character is always appended at the end of destination.
   Destination is not padded with zeros until a total of num characters.

   @param dst   Destination
   @param src   Source
   @param n     Maximum number of characters to copy.

   @return pointer to Destination is returned.
*/
static inline char *my_strncpy_trunc(char *dst, const char *src, size_t num) {
  size_t len = strlen(src);
  if (len >= num) {
    len = num - 1;
    memcpy(dst, src, len);
    dst[len] = '\0';
  } else {
    memcpy(dst, src, len + 1);
  }
  return dst;
}

void my_write_libcoredumper(int sig, const char *path, time_t curr_time) {
  int ret = 0;
  static constexpr std::size_t buf_size = 512;
  char suffix[buf_size];
  char core[buf_size];
  memset(suffix, '\0', buf_size);
  memset(core, '\0', buf_size);
  struct tm *timeinfo = gmtime(&curr_time);

  if (path == nullptr)
    strcpy(core, "core");
  else
    strncpy(core, path, buf_size - 1);

  sprintf(suffix, ".%d%02d%02d%02d%02d%02d", (1900 + timeinfo->tm_year),
      timeinfo->tm_mon, timeinfo->tm_mday, timeinfo->tm_hour,
      timeinfo->tm_min, timeinfo->tm_sec);

  size_t core_len = strlen(core);
  my_strncpy_trunc(core + core_len, suffix, buf_size - core_len);
  static constexpr auto core_msg = "CORE PATH: ";
  [[maybe_unused]] auto r = write(STDERR_FILENO, core_msg, strlen(core_msg));
  r = write(STDERR_FILENO, core, strlen(core));
  r = write(STDERR_FILENO, "\n\n", 2);
  ret = WriteCoreDump(core);
  if (ret != 0) {
    static constexpr auto err_msg = "Error writing coredump.";
    r = write(STDERR_FILENO, err_msg, strlen(err_msg));
  }
}

std::string coredumper_core_path;

extern "C" void handle_fatal_signal(int sig) {
  my_write_libcoredumper(sig, coredumper_core_path.c_str(), time(nullptr));
  _exit(1);  // Using _exit(), since exit() is not async
             // signal safe
}

extern "C" {
  static void empty_signal_handler(int sig [[maybe_unused]]) {
  }

  void set_coredumper_signals(std::string const& core_path) {
    coredumper_core_path = core_path;

    // init signal handler to use coredumper
    struct sigaction sa;
    (void)sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_RESETHAND | SA_NODEFER;
    sa.sa_handler = handle_fatal_signal;
    // Treat these as fatal and handle them.
    sigaction(SIGABRT, &sa, nullptr);
    sigaction(SIGFPE, &sa, nullptr);
    sigaction(SIGBUS, &sa, nullptr);
    sigaction(SIGILL, &sa, nullptr);
    sigaction(SIGSEGV, &sa, nullptr);
    sa.sa_handler = empty_signal_handler;
    (void)sigaction(SIGALRM, &sa, nullptr);
    sa.sa_handler = SIG_DFL;
    (void)sigaction(SIGTERM, &sa, nullptr);
    (void)sigaction(SIGHUP, &sa, nullptr);
    (void)sigaction(SIGUSR1, &sa, nullptr);
    // Ignore SIGPIPE
    sa.sa_flags = 0;
    sa.sa_handler = SIG_IGN;
    (void)sigaction(SIGPIPE, &sa, nullptr);
  }
}
#endif


namespace garb
{

void
become_daemon (const std::string& workdir)
{
    if (chdir("/")) // detach from potentially removable block devices
    {
        gu_throw_error(errno) << "chdir(" << workdir << ") failed";
    }

    if (!workdir.empty() && chdir(workdir.c_str()))
    {
        gu_throw_error(errno) << "chdir(" << workdir << ") failed";
    }

    if (pid_t pid = fork())
    {
        if (pid > 0) // parent
        {
            exit(0);
        }
        else
        {
            // I guess we want this to go to stderr as well;
            std::cerr << "Failed to fork daemon process: "
                      << errno << " (" << strerror(errno) << ")";
            gu_throw_error(errno) << "Failed to fork daemon process";
        }
    }

    // child

    if (setsid()<0) // become a new process leader, detach from terminal
    {
        gu_throw_error(errno) << "setsid() failed";
    }

    // umask(0);

    // A second fork ensures the process cannot acquire a controlling
    // terminal.
    if (pid_t pid = fork())
    {
        if (pid > 0)
        {
            exit(0);
        }
        else
        {
            gu_throw_error(errno) << "Second fork failed";
        }
    }

    // Close the standard streams. This decouples the daemon from the
    // terminal that started it.
    close(0);
    close(1);
    close(2);

    // Bind standard fds (0, 1, 2) to /dev/null
    for (int fd = 0; fd < 3; ++fd)
    {
        if (open("/dev/null", O_RDONLY) < 0)
        {
            gu_throw_error(errno) << "Unable to open /dev/null for fd " << fd;
        }
    }

    char* wd(static_cast<char*>(::malloc(PATH_MAX)));
    if (wd)
    {
        log_info << "Currend WD: " << getcwd(wd, PATH_MAX);
        ::free(wd);
    }
}

int
main (int argc, char* argv[])
{
    Config config(argc, argv);
#if defined(WITH_COREDUMPER) && WITH_COREDUMPER
    if (!config.coredumper().empty()) {
      set_coredumper_signals(config.coredumper());
    }
#endif
    if (config.exit()) return 0;

    log_info << "Read config: " <<  config << std::endl;

    if (config.daemon()) become_daemon(config.workdir());

    try
    {
        /* Ignore SIGPIPE which could be raised when cluster connections are
           closed abruptly. */
        struct sigaction isa;
        memset (&isa, 0, sizeof(isa));
        isa.sa_handler = SIG_IGN;

        if (sigaction (SIGPIPE, &isa, NULL))
        {
            gu_throw_error(errno) << "Falied to install signal handler for signal "
                                  << "SIGPIPE";
        }

        RecvLoop loop (config);
        int rcode = loop.returnCode();
        log_info << "Garbd returns " << rcode;
        return rcode;
    }
    catch (std::exception& e)
    {
        log_fatal << "Garbd exiting with error: " << e.what();
    }
    catch (...)
    {
        log_fatal << "Garbd exiting";
    }

    return EXIT_FAILURE;
}

} /* namespace garb */

/* If the code around is compiled with HAVE_PSI_INTERFACE defined,
   it uses pfs_instr_callback for mutexes and conditions creation.
   If HAVE_PSI_INTERFACE is not defined, the code around uses Galera
   objects directly.
   Because of CMake scripts structure, it is not possible to compile
   Galera lib with HAVE_PSI_INTERFACE defined and garbd with HAVE_PSI_INTERFACE
   not defined. However, for garbd there is no "server side" which is PSI interface
   provider (like for Galera lib).
   The below function mocks PSI interface allowing garbd to work when compiled
   with HAVE_PSI_INTERFACE defined. */
static void dummy_pfs_cb(wsrep_pfs_instr_type_t type, wsrep_pfs_instr_ops_t ops,
                         wsrep_pfs_instr_tag_t tag,
                         void **value __attribute__((unused)),
                         void **alliedvalue __attribute__((unused)),
                         const void *ts __attribute__((unused))) {

  if (type == WSREP_PFS_INSTR_TYPE_MUTEX) {
    assert (value != nullptr);
    switch (ops) {
      case WSREP_PFS_INSTR_OPS_INIT: {
        gu_mutex_t *mutex = new gu_mutex_t();

        gu_mutex_init (mutex, nullptr);
        *value = mutex;

        break;
      }

      case WSREP_PFS_INSTR_OPS_DESTROY: {
        gu_mutex_t *mutex = reinterpret_cast<gu_mutex_t *>(*value);
        assert(mutex != nullptr);

        gu_mutex_destroy (mutex);
        delete mutex;
        *value = nullptr;

        break;
      }

      case WSREP_PFS_INSTR_OPS_LOCK: {
        gu_mutex_t *mutex = reinterpret_cast<gu_mutex_t *>(*value);
        assert(mutex != nullptr);

        gu_mutex_lock(mutex);

        break;
      }

      case WSREP_PFS_INSTR_OPS_UNLOCK: {
        gu_mutex_t *mutex = reinterpret_cast<gu_mutex_t *>(*value);
        assert(mutex != nullptr);

        gu_mutex_unlock(mutex);

        break;
      }

      default:
        assert(0);
        break;
    }
  } else if (type == WSREP_PFS_INSTR_TYPE_CONDVAR) {
    assert (value != nullptr);
    switch (ops) {
      case WSREP_PFS_INSTR_OPS_INIT: {
        gu_cond_t *cond = new gu_cond_t();

        gu_cond_init(cond, nullptr);
        *value = cond;

        break;
      }

      case WSREP_PFS_INSTR_OPS_DESTROY: {
        gu_cond_t *cond = reinterpret_cast<gu_cond_t *>(*value);
        assert(cond != nullptr);

        gu_cond_destroy(cond);
        delete cond;
        *value = nullptr;

        break;
      }

      case WSREP_PFS_INSTR_OPS_WAIT: {
        gu_cond_t *cond = reinterpret_cast<gu_cond_t *>(*value);
        gu_mutex_t *mutex = reinterpret_cast<gu_mutex_t *>(*alliedvalue);
        assert(cond != nullptr && mutex != nullptr);

        gu_cond_wait (cond, mutex);

        break;
      }

      case WSREP_PFS_INSTR_OPS_TIMEDWAIT: {
        gu_cond_t *cond = reinterpret_cast<gu_cond_t *>(*value);
        gu_mutex_t *mutex = reinterpret_cast<gu_mutex_t *>(*alliedvalue);
        const timespec *wtime = reinterpret_cast<const timespec *>(ts);
        assert(cond != nullptr && mutex != nullptr);

        gu_cond_timedwait(cond, mutex, wtime);

        break;
      }

      case WSREP_PFS_INSTR_OPS_SIGNAL: {
        gu_cond_t *cond = reinterpret_cast<gu_cond_t *>(*value);
        assert(cond != nullptr);

        gu_cond_signal(cond);

        break;
      }

      case WSREP_PFS_INSTR_OPS_BROADCAST: {
        gu_cond_t *cond = reinterpret_cast<gu_cond_t *>(*value);
        assert(cond != nullptr);

        gu_cond_broadcast(cond);

        break;
      }

      default:
        assert(0);
        break;
    }
  } else if (type == WSREP_PFS_INSTR_TYPE_THREAD) {
    switch (ops) {
      case WSREP_PFS_INSTR_OPS_INIT:
      case WSREP_PFS_INSTR_OPS_DESTROY:
        break;

      default:
        assert(0);
        break;
    }
  } else if (type == WSREP_PFS_INSTR_TYPE_FILE) {
    switch (ops) {
      case WSREP_PFS_INSTR_OPS_CREATE:
      case WSREP_PFS_INSTR_OPS_OPEN:
      case WSREP_PFS_INSTR_OPS_CLOSE:
      case WSREP_PFS_INSTR_OPS_DELETE:
        break;

      default:
        assert(0);
        break;
    }
  }
}

int
main (int argc, char* argv[])
{
    gu_conf_set_pfs_instr_callback(dummy_pfs_cb);
    try
    {
        return garb::main (argc, argv);
    }
    catch (std::exception& e)
    {
        log_fatal << e.what();
        return 1;
    }
}

