/*

  ----------------------------------------------------
  httpry - HTTP logging and information retrieval tool
  ----------------------------------------------------

  Copyright (c) 2005-2011 Jason Bittel <jason.bittel@gmail.com>

*/

#include <math.h>
#include <sys/types.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <time.h>
#include <unistd.h>
#include "config.h"
#include "error.h"
#include "rate.h"

#define MAX_HOST_LEN 256
#define NUM_BUCKETS 100
#define RATE_THRESHOLD 1

typedef struct host_stats {
        char host[MAX_HOST_LEN + 1];
        unsigned int count;
        time_t first_packet;
        time_t last_packet;
} HOST_STATS;

typedef struct thread_args {
        char *use_infile;
        u_int display_interval;
} THREAD_ARGS;

void *run_stats(void *args);
void init_buckets();
void free_buckets();
void scour_bucket(int i);
int find_bucket(char *host, time_t t);

static pthread_t thread = 0;
static pthread_mutex_t stats_lock;
static HOST_STATS **bb;
static int totals = NUM_BUCKETS;
static THREAD_ARGS thread_args;

/* Spawn a thread for updating and printing rate statistics */
void create_rate_stats_thread(int display_interval, char *use_infile) {
        int s;
        thread_args.use_infile = use_infile;
        thread_args.display_interval = display_interval;

        init_buckets();
                        
        s = pthread_mutex_init(&stats_lock, NULL);
        if (s != 0)
                LOG_DIE("Statistics thread mutex initialization failed with error %d", s);
        
        s = pthread_create(&thread, NULL, run_stats, (void *) &thread_args);
        if (s != 0)
                LOG_DIE("Statistics thread creation failed with error %d", s);

        return;
}

/* Explicitly exit rate statistics thread */
void exit_rate_stats_thread() {
        free_buckets();
        if (thread) pthread_cancel(thread);

        return;
}

/* Allocate and initialize all host stats buckets */
void init_buckets() {
        u_int i;

        /* Create bucket brigade (final bucket is for totals) */
        if ((bb = malloc(sizeof(HOST_STATS *) * (NUM_BUCKETS + 1))) == NULL)
                LOG_DIE("Cannot allocate memory for stats array");

        for (i = 0; i <= NUM_BUCKETS; i++) {
                if ((bb[i] = (HOST_STATS *) malloc(sizeof(HOST_STATS))) == NULL)
                        LOG_DIE("Cannot allocate memory for host stats bucket");

                scour_bucket(i);
        }

        return;
}

void free_buckets() {
        u_int i;

        if (!bb) return;

        for (i = 0; i <= NUM_BUCKETS; i++) {
                free(bb[i]);
        }

        free(bb);

        return;
}

/* Clean out a bucket while avoiding obvious memory leak */
void scour_bucket(int i) {
        bb[i]->host[0] = '\0';
        bb[i]->count = 0;
        bb[i]->first_packet = (time_t) 0;
        bb[i]->last_packet = (time_t) 0;
 
        return;
}

/* This is our statistics thread */
void *run_stats (void *args) {
        THREAD_ARGS *thread_args = (THREAD_ARGS *) args;

        while (1) {
                sleep(thread_args->display_interval);
                display_rate_stats(thread_args->use_infile);
        }
        
        return 0;
}

/* Display the running average within each valid bucket */
void display_rate_stats(char *use_infile) {
        u_int i, delta, rps;
        char st_time[MAX_TIME_LEN];
        time_t now;

        if (!thread) return;
        if (!bb) return;

        pthread_mutex_lock(&stats_lock);

        if (use_infile) {
                now = bb[totals]->last_packet;
        } else {
                now = time(NULL);
        }

        struct tm *raw_time = localtime(&now);
        strftime(st_time, MAX_TIME_LEN, "%Y-%m-%d %H:%M:%S", raw_time);

        for (i = 0; i < NUM_BUCKETS; i++) {
                /* Only process valid buckets */
                if ((strlen(bb[i]->host) == 0) || (bb[i]->count == 0)) continue;

                /* Calculate the rate for this host */
                delta = now - bb[i]->first_packet;
                if (delta == 0)
                        continue;
                rps = (u_int) ceil(bb[i]->count / (float) delta);

                if (rps > RATE_THRESHOLD)
                        printf("%s%s%s%s%u rps\n", st_time, FIELD_DELIM, bb[i]->host, FIELD_DELIM, rps);
        }

        /* Display rate totals */
        delta = (u_int) (now - bb[totals]->first_packet);
        if (delta > 0)
                printf("%s%stotals%s%3.2f rps\n", st_time, FIELD_DELIM, FIELD_DELIM, (float) bb[totals]->count / delta);

        pthread_mutex_unlock(&stats_lock);

        return;
}

/* Add or update host data in a bucket */
void add_to_bucket(char *host, time_t t) {
        int bucket;

        if (!bb) return;
        if (host == NULL) return;

        pthread_mutex_lock(&stats_lock);
 
        /* Get a bucket to put host data in */
        bucket = find_bucket(host, t);

        bb[bucket]->last_packet = t;
        bb[bucket]->count++;
        bb[totals]->last_packet = t;
        bb[totals]->count++;

        pthread_mutex_unlock(&stats_lock);

        return;
}

/* Look for a best fit bucket for this host name */
int find_bucket(char *host, time_t t) {
        int i, unused = -1, oldest = -1, bucket;
        time_t oldest_pkt = 0;

#ifdef DEBUG
        ASSERT(host);
        ASSERT(strlen(host) > 0);
        ASSERT(t);
#endif

        for (i = 0; i < NUM_BUCKETS; i++) {
                if (strncmp(host, bb[i]->host, MAX_HOST_LEN) == 0) {
                        return i;
                } else if ((unused == -1) && (strlen(bb[i]->host) == 0)) {
                        unused = i;
                } else if ((bb[i]->last_packet != 0) && ((oldest_pkt == 0) || (bb[i]->last_packet < oldest_pkt))) {
                        oldest_pkt = bb[i]->last_packet;
                        oldest = i;                     
                }
        }

        if (unused > -1) {
#if 0
                PRINT("No matching host bucket found: using unused bucket");
#endif
                bucket = unused;
        } else {
#if 0
                PRINT("No matching host bucket found: using oldest bucket");
#endif
                bucket = oldest;
        }

        scour_bucket(bucket);
        bb[bucket]->first_packet = t;
        strncpy(bb[bucket]->host, host, MAX_HOST_LEN);

        if (bb[totals]->first_packet == 0)
                bb[totals]->first_packet = t;

        return bucket;
}
