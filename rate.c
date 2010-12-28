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
#include "error.h"

#define NUM_BUCKETS 100
#define WAIT_TIME 10
#define THRESHOLD 1
#define ALARM 60
#define BINDSNAP 1
#define MARK_STATS 60

typedef struct host_stats HOST_STATS;
struct host_stats {
        char host[256];
        unsigned int count;
        unsigned int rps;
        time_t first_packet;
        time_t last_packet;
        time_t alarm_set;
};

void *run_stats();
int calculate_averages();
void init_buckets();
void scour_bucket(int i);
int find_bucket(char *host);

static pthread_mutex_t stats_lock;
static HOST_STATS **bb;
static int totals = NUM_BUCKETS;

void create_rate_stats_thread() {
        int s;
        pthread_t thread;

        // initialize buckets and mark overall stats bucket
        init_buckets();  
//        totals = NUM_BUCKETS;
                        
        s = pthread_mutex_init(&stats_lock, NULL);
        if (s != 0)
                LOG_DIE("Statistics thread mutex initialization failed with error %d", s);
 
        s = pthread_create(&thread, NULL, run_stats, (void *) 0);
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
        bb[i]->rps = 0;
        bb[i]->first_packet = time(0);
        bb[i]->last_packet = (time_t) 0;
        bb[i]->alarm_set = (time_t) 0;
        
        return;
}

/* This is our statistics thread */
void *run_stats () {
        while (1) {
                pthread_mutex_lock(&stats_lock);
                calculate_averages();
                pthread_mutex_unlock(&stats_lock);
                sleep(WAIT_TIME);
        }
}

/* calculate the running average within each bucket */
int calculate_averages() {
        u_int i,delta;
        char st_time[10];
        time_t now = time(0);
        struct tm *raw_time = localtime(&now);
        snprintf(st_time, 9, "%02d:%02d:%02d",raw_time->tm_hour,raw_time->tm_min,raw_time->tm_sec);

        for (i=0; i<NUM_BUCKETS; i++) {

                // only process valid buckets
                if ( strlen(bb[i]->host) >0 ) {
                        delta = now - bb[i]->first_packet;

                        // let's try to avoid a divide-by-zero, shall we?
                        if (delta > 1 ) {
        
                                // round our average and save it in the bucket
                                bb[i]->rps = (u_int)ceil( (bb[i]->count) / (float)delta);

                                // handle threshold crossing
                                if ( bb[i]->rps > THRESHOLD ) {

        
                                        // display detail to either syslog or stdout
                                        if ( BINDSNAP > 0) {
                                                printf("[%s] customer [%s] - %u rps\n",st_time,bb[i]->host,bb[i]->rps);
                                                fflush(stdout);
                                        }
                                        else {
                                                // if running in background, use alarm reset timer
                                                if ((now-bb[i]->alarm_set) > ALARM) {

                                                        syslog(LOG_NOTICE,"customer [%s] - %u rps\n",bb[i]->host,bb[i]->rps);

                                                        // reset alarm
                                                        bb[i]->alarm_set = now;
                                                }
                                        }
                                }
                        }
                }               
        }

        /* 'mark stats' if required and it is time */
        delta = (u_int)(now - bb[totals]->first_packet);
        if ((MARK_STATS > 0) && (delta > 1) && (delta >= MARK_STATS) ) {
        
                // handle bindsnap mode 
                if (BINDSNAP > 0) {
                        printf("[%s] totals - %3.2f rps\n",st_time, ((float)bb[totals]->count/delta));
                        fflush(stdout);
                }
                else {
                        syslog(LOG_NOTICE,"[totals] - %3.2f rps\n", ((float)bb[totals]->count/delta));
                }       
                scour_bucket(totals);
        }

        return 1;
}

// add a packet to a bucket
int add_to_bucket(char *host) {
        int bucket = 0;

        if ( host == NULL) {
          return 0;
        }

        // get the bucket to put packet in      
        pthread_mutex_lock(&stats_lock);
        bucket = find_bucket(host);

        // set bucket fields
        bb[bucket]->last_packet = time(0);
        bb[bucket]->count++;
        bb[totals]->count++;

        pthread_mutex_unlock(&stats_lock);

        return 1;
}

// figure out where to put this request
int find_bucket(char *host) {
        int i, bucket=0;
        time_t oldest=0;

        // look for an existing bucket for this IP
        for (i=0; i< NUM_BUCKETS; i++ ){
                // host field of bucket seems to match the host we are checking
                if (strncmp(host,bb[i]->host,254) == 0 ) {
                        return i;
                }
        }

        // look for unused buckets
        for (i=0; i< NUM_BUCKETS; i++ ) {

                // found an unused one - clean it, init it, and return it
                if ( strlen(bb[i]->host) == 0 ) {
                        scour_bucket(i);
                        strncpy(bb[i]->host,host,254);
                        return i;
                }

                if ( ( bb[i]->last_packet != 0 ) && ((oldest==0)||( bb[i]->last_packet < oldest))) {
                        oldest = bb[i]->last_packet;
                        bucket = i;                     
                }
        }

        // use the most stagnant bucket since all are in use
        // clean it, init it, and return it
        scour_bucket(bucket);
        strncpy(bb[i]->host,host,254);

        return bucket;
}
