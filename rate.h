/*

  ----------------------------------------------------
  httpry - HTTP logging and information retrieval tool
  ----------------------------------------------------

  Copyright (c) 2005-2014 Jason Bittel <jason.bittel@gmail.com>
  Licensed under GPLv2. For further information, see COPYING file.

*/

#ifndef _HAVE_RATE_H
#define _HAVE_RATE_H

void init_rate_stats(int display_interval, char *use_infile, int rate_threshold);
void cleanup_rate_stats();
void display_rate_stats(char *use_infile, int rate_threshold);
void update_host_stats(char *host, time_t t);

#endif /* ! _HAVE_RATE_H */
