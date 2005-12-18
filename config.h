/*

  ----------------------------------------------------
  httpry - HTTP logging and information retrieval tool
  ----------------------------------------------------

  config.h 11/16/2005

  Copyright (c) 2005, Jason Bittel <jbittel@corban.edu>. All rights reserved.
  See included LICENSE file for specific licensing information

  Most of these shouldn't be changed from the defaults, I'm warning you

*/

#define PROG_NAME "httpry"
#define PROG_VER "0.0.7"

/* Directory to switch to when running in daemon mode
   *** Can be overridden with -r */
#define RUN_DIR "/"

/* Location to store the PID file when running in daemon mode */
#define PID_FILE "/var/run/httpry.pid"

/* Where to send unnecessary output */
#define NULL_FILE "/dev/null"

/* Default packet capture filter; must be standard Pcap format
   *** Can be overridden with -l */
#define DEFAULT_CAPFILTER "tcp dst port 80"

/* Line terminator for HTTP header; should never change! */
#define DELIM "\r\n"

/* Get request string in HTTP header; should never change! */
#define GET_REQUEST "GET "

/* Head request string in HTTP header; should never change! */
#define HEAD_REQUEST "HEAD "
