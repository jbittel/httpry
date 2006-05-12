/*

  ----------------------------------------------------
  httpry - HTTP logging and information retrieval tool
  ----------------------------------------------------

  httpry.h | created: 5/3/2005

  Copyright (c) 2006, Jason Bittel <jbittel@corban.edu>. All rights reserved.
  See included LICENSE file for specific licensing information

*/

/* RFC2616 request line fields; request header fields
 * are parsed dynamically according to the format string */
typedef struct http_hdr HTTP;
struct http_hdr {
        char *method;
        char *uri;
        char *version;
};
