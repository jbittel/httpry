/*

  ----------------------------------------------------
  httpry - HTTP logging and information retrieval tool
  ----------------------------------------------------

  Copyright (c) 2005-2009 Jason Bittel <jason.bittel@gmail.com>

*/

#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <time.h>
#include <unistd.h>
#include "config.h"
#include "error.h"

#define MAX_HOST_LEN 256
#define NUM_BUCKETS 100
#define DISPLAY_INTERVAL 10
#define TOTALS_DISPLAY_INTERVAL 60
#define RATE_THRESHOLD 1

typedef struct host_stats HOST_STATS;
struct host_stats {
        char host[MAX_HOST_LEN + 1];
        unsigned int count;
        time_t first_packet;
        time_t last_packet;
};

void run_stats();
void calculate_averages();
void init_buckets();
void scour_bucket(int i);
int find_bucket(char *host);

static pthread_mutex_t stats_lock;
static HOST_STATS **bb;
static int totals = NUM_BUCKETS;

/* Spawn a thread for updating and printing rate statistics */
void create_rate_stats_thread() {
        int s;
        pthread_t thread;

        init_buckets();  
                        
        s = pthread_mutex_init(&stats_lock, NULL);
        if (s != 0)
                LOG_DIE("Statistics thread mutex initialization failed with error %d", s);
 
        s = pthread_create(&thread, NULL, (void *) run_stats, (void *) 0);
        if (s != 0)
                LOG_DIE("Statistics thread creation failed with error %d", s);

        return;
}

/* Allocate and initialize all host stats buckets */
void init_buckets() {
        u_int i;

        /* Create bucket brigade (final bucket is for totals) */
        if ((bb = malloc( sizeof(HOST_STATS *) * (NUM_BUCKETS + 1))) == NULL)
                LOG_DIE("Cannot allocate memory for stats array");

        for (i = 0; i <= NUM_BUCKETS; i++) {
                if ((bb[i] = (HOST_STATS *) malloc(sizeof(HOST_STATS))) == NULL)
                        LOG_DIE("Cannot allocate memory for host stats bucket");

                scour_bucket(i);
        }

        return;
}

/* Clean out a bucket while avoiding obvious memory leak */
void scour_bucket(int i) {
        bb[i]->host[0] = '\0';
        bb[i]->count = 0;
        bb[i]->first_packet = time(0);
        bb[i]->last_packet = (time_t) 0;
 
        return;
}

/* This is our statistics thread */
void run_stats () {
        while (1) {
                pthread_mutex_lock(&stats_lock);
                calculate_averages();
                pthread_mutex_unlock(&stats_lock);
                sleep(DISPLAY_INTERVAL);
        }
}

/* Calculate the running average within each bucket */
void calculate_averages() {
        u_int i, delta, rps;
        char st_time[MAX_TIME_LEN];
        time_t now = time(0);
        struct tm *raw_time = localtime(&now);

        strftime(st_time, MAX_TIME_LEN, "%Y-%m-%d %H:%M:%S", raw_time);

        for (i = 0; i < NUM_BUCKETS; i++) {
                if (strlen(bb[i]->host) == 0) /* Only process valid buckets */
                        continue;

                delta = now - bb[i]->first_packet;
                if (delta == 0) /* Let's try to avoid a divide-by-zero, shall we? */
                        continue;

                /* Calculate the average rate for this host */
                rps = (u_int) ceil(bb[i]->count / (float) delta);

                if (rps > RATE_THRESHOLD)
                        printf("%s%s%s%s%u rps\n", st_time, FIELD_DELIM, bb[i]->host, FIELD_DELIM, rps);
        }

        /* Display rate totals as necessary */
        delta = (u_int) (now - bb[totals]->first_packet);
        if (delta == 0)
                return;

        if ((delta > 1) && (delta >= TOTALS_DISPLAY_INTERVAL)) {
                printf("%s%stotals%s%3.2f rps\n", st_time, FIELD_DELIM, FIELD_DELIM, (float) bb[totals]->count / delta);
                scour_bucket(totals);
        }

        return;
}

/* Add or update host data in a bucket */
void add_to_bucket(char *host) {
        int bucket;

        if (host == NULL)
                return;

        pthread_mutex_lock(&stats_lock);
 
        /* Get a bucket to put host data in */
        bucket = find_bucket(host);

        bb[bucket]->last_packet = time(0);
        bb[bucket]->count++;
        bb[totals]->count++;

        pthread_mutex_unlock(&stats_lock);

        return;
}

/* Look for a best fit bucket for this host name */
int find_bucket(char *host) {
        int i, unused = -1, oldest = -1, bucket;
        time_t oldest_pkt = 0;

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
#ifdef DEBUG
                LOG_PRINT("No matching host bucket: found unused bucket");
#endif
                bucket = unused;
        } else {
#ifdef DEBUG
                LOG_PRINT("No matching host bucket: reusing oldest bucket [%s]", bb[oldest]->host);
#endif
                bucket = oldest;
        }

        scour_bucket(bucket);
        strncpy(bb[bucket]->host, host, MAX_HOST_LEN);

        return bucket;
}
