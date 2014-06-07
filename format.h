/*

  ----------------------------------------------------
  httpry - HTTP logging and information retrieval tool
  ----------------------------------------------------

  Copyright (c) 2005-2014 Jason Bittel <jason.bittel@gmail.com>
  Licensed under GPLv2. For further information, see COPYING file.

*/

#ifndef _HAVE_FORMAT_H
#define _HAVE_FORMAT_H

void parse_format_string(char *str);
void insert_value(char *name, char *value);
char *get_value(char *name);
void clear_values();
void print_format_list();
void print_format_values();
void free_format();

#endif /* ! _HAVE_FORMAT_H */
