/*

  ----------------------------------------------------
  httpry - HTTP logging and information retrieval tool
  ----------------------------------------------------

  Copyright (c) 2005-2009 Jason Bittel <jason.bittel@gmail.com>

*/

#ifndef _HAVE_RATE_H
#define _HAVE_RATE_H

void create_rate_stats_thread();
int add_to_bucket(char *host);

#endif /* ! _HAVE_RATE_H */
