/*

  ----------------------------------------------------
  httpry - HTTP logging and information retrieval tool
  ----------------------------------------------------

  Copyright (c) 2005-2014 Jason Bittel <jason.bittel@gmail.com>

*/

#ifndef _HAVE_METHODS_H
#define _HAVE_METHODS_H

void parse_methods_string(char *str);
int is_request_method(const char *str);
void free_methods();

#endif /* ! _HAVE_METHODS_H */
