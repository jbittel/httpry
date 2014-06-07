/*

  ----------------------------------------------------
  httpry - HTTP logging and information retrieval tool
  ----------------------------------------------------

  Copyright (c) 2005-2014 Jason Bittel <jason.bittel@gmail.com>
  Licensed under GPLv2. For further information, see COPYING file.

*/

#ifndef _HAVE_ERROR_H
#define _HAVE_ERROR_H

#include <signal.h>
#include <syslog.h>
#include "config.h"

extern int quiet_mode;
extern int use_syslog;

/* Macros for logging/displaying status messages */
#define PRINT(x...) { if (!quiet_mode) { fprintf(stderr, x); fprintf(stderr, "\n"); } }
#define WARN(x...) { fprintf(stderr, "Warning: " x); fprintf(stderr, "\n"); }
#define LOG(x...) { if (use_syslog) { openlog(PROG_NAME, LOG_PID, LOG_DAEMON); syslog(LOG_ERR, x); closelog(); } }
#define DIE(x...) { fprintf(stderr, "Error: " x); fprintf(stderr, "\n"); raise(SIGINT); }
#define LOG_PRINT(x...) { LOG(x); PRINT(x); }
#define LOG_WARN(x...) { LOG(x); WARN(x); }
#define LOG_DIE(x...) { LOG(x); DIE(x); }

/* Assert macro for testing and debugging; use 'make debug'
   to compile the program with debugging features enabled */
#ifdef DEBUG
#define ASSERT(x)                                                    \
        if (!(x)) {                                                  \
                fflush(NULL);                                        \
                fprintf(stderr, "\nAssertion failed: %s, line %d\n", \
                                __FILE__, __LINE__);                 \
                fflush(stderr);                                      \
                exit(EXIT_FAILURE);                                  \
        }
#endif

#endif /* ! _HAVE_ERROR_H */
