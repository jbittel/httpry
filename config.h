/*

  ----------------------------------------------------
  httpry - HTTP logging and information retrieval tool
  ----------------------------------------------------

  config.h | created: 11/16/2005

  Copyright (c) 2006, Jason Bittel <jbittel@corban.edu>. All rights reserved.
  See included LICENSE file for specific licensing information

  Compile time default values for httpry. Many of these can be changed using
  arguments or a config file, so you shouldn't need to change them here. In
  fact, most of these should *not* be changed from the defaults...I'm warning
  you!

*/

#define PROG_NAME "httpry"
#define PROG_VER "0.0.9"

/* Directory to switch to when running in daemon mode
   *** Can be overridden with -r */
#define RUN_DIR "/"

/* Location to store the PID file when running in daemon mode */
#define PID_FILE "/var/run/httpry.pid"

/* Where to send unnecessary output */
#define NULL_FILE "/dev/null"

/* Default packet capture filter; must be standard Pcap format
   *** Can be overridden with -l */
#define DEFAULT_CAPFILTER "tcp port 80 or port 8080"

/* Default output format string
   *** Can be overridden with -s */
#define DEFAULT_FORMAT "Timestamp,Source-IP,Dest-IP,Direction,Method,Host,Request-URI,HTTP-Version,Status-Code,Reason-Phrase"

/* Line terminator for HTTP header; should never change! */
#define DELIM "\r\n"

/* Get request string in HTTP header; should never change! */
#define GET_STRING "GET "

/* Head request string in HTTP header; should never change! */
#define HEAD_STRING "HEAD "

/* Start of HTTP version string in response header; should never change! */
#define HTTP_STRING "HTTP/"
