/*

  ----------------------------------------------------
  httpry - HTTP logging and information retrieval tool
  ----------------------------------------------------

  httpry.h | created: 5/3/2005

  Copyright (c) 2006, Jason Bittel <jbittel@corban.edu>. All rights reserved.
  See included LICENSE file for specific licensing information

*/

/* RFC2616 client request fields */
typedef struct http_client_request HTTP_CLIENT;
struct http_client_request {
        char *method;
        char *request_uri;
        char *http_version;
};

/* RFC2616 server response fields */
typedef struct http_server_response HTTP_SERVER;
struct http_server_response {
        char *http_version;
        char *status_code;
        char *reason_phrase;
};
