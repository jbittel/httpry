/*

  ----------------------------------------------------
  httpry - HTTP logging and information retrieval tool
  ----------------------------------------------------

  Copyright (c) 2005-2011 Jason Bittel <jason.bittel@gmail.com>

*/

#ifndef _HAVE_RATE_H
#define _HAVE_RATE_H

void create_rate_stats_thread(int display_interval, char *use_infile);
void exit_rate_stats_thread();
void display_rate_stats(char *use_infile);
void add_to_bucket(char *host, time_t t);

#endif /* ! _HAVE_RATE_H */
