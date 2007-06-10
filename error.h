/*

  ----------------------------------------------------
  httpry - HTTP logging and information retrieval tool
  ----------------------------------------------------

  Copyright (c) 2005-2007 Jason Bittel <jason.bittel@gmail.com>

*/

#include <signal.h>
#include <syslog.h>
#include "config.h"

/* Macros for logging/displaying status messages */
#define INFO(x...) fprintf(stderr, x); fprintf(stderr, "\n");
#define WARN(x...) fprintf(stderr, "Warning: " x); fprintf(stderr, "\n");
#define LOG(x...) { openlog(PROG_NAME, LOG_PID, LOG_DAEMON); syslog(LOG_ERR, x); closelog(); }
#define DIE(x...) { fprintf(stderr, "Error: " x); fprintf(stderr, "\n"); raise(SIGINT); }
#define LOG_WARN(x...) { LOG(x); WARN(x); }
#define LOG_DIE(x...) { LOG(x); DIE(x); }
