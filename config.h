/*

  ----------------------------------------------------
  httpry - HTTP logging and information retrieval tool
  ----------------------------------------------------

  Copyright (c) 2005-2008 Jason Bittel <jason.bittel@gmail.com>

*/

#ifndef _HAVE_CONFIG_H
#define _HAVE_CONFIG_H

#define PROG_NAME "httpry"
#define PROG_VER "0.1.4"

/* Default packet capture filter; must be a standard libpcap style filter
   *** Can be overridden */
#define DEFAULT_CAPFILTER "tcp port 80 or 8080"

/* Default output format string; see doc/format-string for more info
   *** Can be overridden with -s */
#define DEFAULT_FORMAT "timestamp,source-ip,dest-ip,direction,method,host,request-uri,http-version,status-code,reason-phrase"

/* Default request methods; a comma-delimited list similar to the format string
   *** Can be overridden with -m */
#define DEFAULT_METHODS "GET,HEAD,POST"

/* Location to store the PID file when running in daemon mode */
#define PID_FILE "/var/run/httpry.pid"

/* Where to send unnecessary output */
#define NULL_FILE "/dev/null"

/* HTTP specific constants; should never change! */
#define HTTP_STRING "HTTP/"

#endif /* ! _HAVE_CONFIG_H */
