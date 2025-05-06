/* Copyright (C) 2013-2015 Codership Oy <info@codership.com>

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; version 2 of the License.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License along
   with this program; if not, write to the Free Software Foundation, Inc.,
   51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA. */

#ifndef PROCASS_H
#define PROCASS_H

#include <spawn.h>
#include <sys/types.h>
#include <cassert>
#include <cstddef>
#include <cstdio>
#include <cstdlib>

/* A small class to run external programs. */
class process {
 private:
  const char *const str_;
  FILE *io_;
  FILE *io_w_;

  /* Read end of STDERR */
  FILE *io_err_;

  int err_;
  pid_t pid_;

 public:
  /*! @arg type is a pointer to a null-terminated string which must contain
           either the letter 'r' for reading, or the letter 'w' for writing,
           or the letters 'rw' for both reading and writing.
      @arg env optional null-terminated vector of environment variables
      @arg execute_immediately  If this is set to true, then the command will
           be executed while in the constructor.
           Executing the command from the constructor caused problems
           due to dealing with errors, so the ability to execute the
           command separately was added.
   */
  process(const char *cmd, const char *type, char **env,
          bool execute_immediately = true);
  ~process();

  /* If type is 'r' or 'rw' this is the read pipe
     Else if type is 'w', this is the write pipe
  */
  FILE *pipe() { return io_; }

  /* If type is 'rw' this is the write pipe
     Else if type is 'r' or 'w' this is NULL
     This variable is only set if the type is 'rw'
  */
  FILE *write_pipe() { return io_w_; }

  /* This is the read end of a stderr pipe.
     The process being started will write to stderr.
     This is where we will read from stderr.
     All processses will have their stderr redirected to this pipe.
  */
  FILE *err_pipe() { return io_err_; }

  /* Closes the write pipe so that the other side will get an EOF
     (and not hang while waiting for the rest of the data).
  */
  void close_write_pipe();

  /* Clears the err_pipe.  This does NOT close the err pipe. This means
     that this class is no longer responsible for closing the pipe.
  */
  void clear_err_pipe() { io_err_ = NULL; }

  void execute(const char *type, char **env);

  int error() { return err_; }
  int wait();
  const char *cmd() { return str_; }
  void terminate();
  void interrupt();
  bool waitable() { return (pid_ != 0); }
};

#endif /* PROCASS_H */
