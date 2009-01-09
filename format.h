/*

  ----------------------------------------------------
  httpry - HTTP logging and information retrieval tool
  ----------------------------------------------------

  Copyright (c) 2005-2009 Jason Bittel <jason.bittel@gmail.com>

*/

#ifndef _HAVE_FORMAT_H
#define _HAVE_FORMAT_H

void parse_format_string(char *str);
void insert_value(char *name, char *value);
void print_format_list();
void print_format_values();
void free_format();

#endif /* ! _HAVE_FORMAT_H */
