/*

  ----------------------------------------------------
  httpry - HTTP logging and information retrieval tool
  ----------------------------------------------------

  config.h | created: 11/16/2005

  Copyright (c) 2006, Jason Bittel <jbittel@corban.edu>. All rights reserved.

  Redistribution and use in source and binary forms, with or without
  modification, are permitted provided that the following conditions are
  met:

  1. Redistributions of source code must retain the above copyright notice,
     this list of conditions and the following disclaimer.

  2. Redistributions in binary form must reproduce the above copyright notice,
     this list of conditions and the following disclaimer in the documentation
     and/or other materials provided with the distribution.

  3. Neither the name of the author nor the names of its
     contributors may be used to endorse or promote products derived from
     this software without specific prior written permission.

  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS
  IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
  THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
  PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE
  LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
  CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
  SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
  INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
  CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
  ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
  POSSIBILITY OF SUCH DAMAGE.

*/

/*
  Compile time default values for httpry. Many of these can be changed using
  arguments or a config file, so you shouldn't need to change them here. In
  fact, most of these should *not* be changed from the defaults...I'm warning
  you!
*/

#define PROG_NAME "httpry"
#define PROG_VER "0.0.9"
#define XML_VER "0.1"

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
