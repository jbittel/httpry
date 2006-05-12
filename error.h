/*

  ----------------------------------------------------
  httpry - HTTP logging and information retrieval tool
  ----------------------------------------------------

  error.h | created: 5/10/2006

  Copyright (c) 2006, Jason Bittel <jbittel@corban.edu>. All rights reserved.
  See included LICENSE file for specific licensing information

*/

#include <signal.h>
#include <syslog.h>
#include "config.h"

/* Macros for logging/displaying status messages */
#define info(x...) fprintf(stderr, x)
#define warn(x...) fprintf(stderr, "Warning: " x)
#define log(x...) { openlog(PROG_NAME, LOG_PID, LOG_DAEMON); syslog(LOG_ERR, x); closelog(); }
#define die(x...) { fprintf(stderr, "Error: " x); raise(SIGINT); }
#define log_die(x...) { log(x); die(x); }
