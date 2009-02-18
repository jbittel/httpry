/*

  ----------------------------------------------------
  httpry - HTTP logging and information retrieval tool
  ----------------------------------------------------

  Copyright (c) 2005-2009 Jason Bittel <jason.bittel@gmail.com>

*/

#ifndef _HAVE_CONFIG_H
#define _HAVE_CONFIG_H

#define PROG_NAME "httpry"
#define PROG_VER "0.1.5"

/* Default packet capture filter; must be a standard libpcap style filter
   *** Can be overridden */
#define DEFAULT_CAPFILTER "tcp port 80 or 8080"

/* Default output format string; see doc/format-string for more information
   *** Can be overridden with -f */
#define DEFAULT_FORMAT "timestamp,source-ip,dest-ip,direction,method,host,request-uri,http-version,status-code,reason-phrase"

/* Default request methods to process; see doc/method-string for more information
   *** Can be overridden with -m */
#define DEFAULT_METHODS "options,get,head,post,put,delete,trace,connect"

/* Location to store the PID file when running in daemon mode */
#define PID_FILE "/var/run/httpry.pid"

/* Where to send unnecessary output */
#define NULL_FILE "/dev/null"

/* Character to print when an output field has no associated data */
#define EMPTY_FIELD '-'

/* Delimiter that separates output fields */
#define FIELD_DELIM "\t"

/* HTTP specific constant; should never change! */
#define HTTP_STRING "HTTP/"

#endif /* ! _HAVE_CONFIG_H */
