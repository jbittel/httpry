/*

  ----------------------------------------------------
  httpry - HTTP logging and information retrieval tool
  ----------------------------------------------------

  Copyright (c) 2005-2014 Jason Bittel <jason.bittel@gmail.com>
  Licensed under GPLv2. For further information, see COPYING file.

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
#include "rate.h"
#include "utility.h"

#define MAX_HOST_LEN 255
#define HASHSIZE 2048
#define NODE_BLOCKSIZE 100
#define NODE_ALLOC_BLOCKSIZE 10

struct host_stats {
        char host[MAX_HOST_LEN + 1];
        unsigned int count;
        time_t first_packet;
        time_t last_packet;
        struct host_stats *next;
};

struct thread_args {
        char *use_infile;
        unsigned int rate_interval;
        int rate_threshold;
};

void create_rate_stats_thread(int rate_interval, char *use_infile, int rate_threshold);
void exit_rate_stats_thread();
void *run_stats(void *args);
struct host_stats *remove_node(struct host_stats *node, struct host_stats *prev);
struct host_stats *get_host(char *str);
struct host_stats *get_node();

static pthread_t thread;
static int thread_created = 0;
static pthread_mutex_t stats_lock;
static struct host_stats **stats = NULL;
static struct host_stats *free_stack = NULL;
static struct host_stats **block_alloc = NULL;
static struct host_stats totals;
static struct thread_args thread_args;

/* Initialize rate stats counters and structures, and
   start up the stats thread if necessary */
void init_rate_stats(int rate_interval, char *use_infile, int rate_threshold) {
        /* Initialize host totals */
        totals.count = 0;
        totals.first_packet = 0;
        totals.last_packet = 0;

        /* Allocate host stats hash array */
        if ((stats = (struct host_stats **) calloc(HASHSIZE, sizeof(struct host_stats *))) == NULL)
                LOG_DIE("Cannot allocate memory for host stats");

        if (!use_infile)
                create_rate_stats_thread(rate_interval, use_infile, rate_threshold);

        return;
}

/* Spawn a thread for updating and printing rate statistics */
void create_rate_stats_thread(int rate_interval, char *use_infile, int rate_threshold) {
        sigset_t set;
        int s;

        if (thread_created) return;

        thread_args.use_infile = use_infile;
        thread_args.rate_interval = rate_interval;
        thread_args.rate_threshold = rate_threshold;

        sigemptyset(&set);
        sigaddset(&set, SIGINT);
        sigaddset(&set, SIGHUP);

        s = pthread_mutex_init(&stats_lock, NULL);
        if (s != 0)
                LOG_DIE("Statistics thread mutex initialization failed with error %d", s);

        s = pthread_sigmask(SIG_BLOCK, &set, NULL);
        if (s != 0)
                LOG_DIE("Statistics thread signal blocking failed with error %d", s);

        s = pthread_create(&thread, NULL, run_stats, (void *) &thread_args);
        if (s != 0)
                LOG_DIE("Statistics thread creation failed with error %d", s);

        s = pthread_sigmask(SIG_UNBLOCK, &set, NULL);
        if (s != 0)
                LOG_DIE("Statistics thread signal unblocking failed with error %d", s);

        thread_created = 1;

        return;
}

/* Attempt to cancel the stats thread, cleanup allocated
   memory and clear necessary counters and structures */
void cleanup_rate_stats() {
        struct host_stats **i;

        exit_rate_stats_thread();

        if (block_alloc != NULL) {
                for (i = block_alloc; *i; i++) {
                        free(*i);
                }

                free(block_alloc);
                block_alloc = NULL;
        }

        if (stats != NULL) {
                free(stats);
                stats = NULL;
        }

        free_stack = NULL;

        return;
}

/* Explicitly exit rate statistics thread */
void exit_rate_stats_thread() {
        int s;
        void *retval;

        if (!thread_created) return;

        s = pthread_cancel(thread);
        if (s != 0)
                LOG_WARN("Statistics thread cancellation failed with error %d", s);

        s = pthread_join(thread, &retval);
        if (s != 0)
                LOG_WARN("Statistics thread join failed with error %d", s);

        if (retval != PTHREAD_CANCELED)
                LOG_WARN("Statistics thread exit value was unexpected");

        thread_created = 0;

        s = pthread_mutex_destroy(&stats_lock);
        if (s != 0)
                LOG_WARN("Statistcs thread mutex destroy failed with error %d", s);

        return;
}

/* This is our statistics thread */
void *run_stats (void *args) {
        struct thread_args *thread_args = (struct thread_args *) args;

        while (1) {
                sleep(thread_args->rate_interval);
                display_rate_stats(thread_args->use_infile, thread_args->rate_threshold);
        }

        return (void *) 0;
}

/* Display the running average within each valid stats node */
void display_rate_stats(char *use_infile, int rate_threshold) {
        time_t now;
        char st_time[MAX_TIME_LEN];
        unsigned int delta, rps = 0;
        int i;
        struct host_stats *node, *prev;

        if (stats == NULL) return;

        if (thread_created)
                pthread_mutex_lock(&stats_lock);

        if (use_infile) {
                now = totals.last_packet;
        } else {
                now = time(NULL);
        }

        strftime(st_time, MAX_TIME_LEN, "%Y-%m-%d %H:%M:%S", localtime(&now));

#ifdef DEBUG
        int j, num_buckets = 0, num_chain, max_chain = 0, num_nodes = 0;

        for (j = 0; j < HASHSIZE; j++) {
                if (stats[j]) num_buckets++;

                num_chain = 0;
                for (node = stats[j]; node != NULL; node = node->next) num_chain++;
                if (num_chain > max_chain) max_chain = num_chain;
                num_nodes += num_chain;
        }

        PRINT("----------------------------");
        PRINT("Hash buckets:       %d", HASHSIZE);
        PRINT("Nodes inserted:     %d", num_nodes);
        PRINT("Buckets in use:     %d", num_buckets);
        PRINT("Hash collisions:    %d", num_nodes - num_buckets);
        PRINT("Longest hash chain: %d", max_chain);
        PRINT("----------------------------");
#endif

        /* Display rate stats for each valid host */
        for (i = 0; i < HASHSIZE; i++) {
                node = stats[i];
                prev = NULL;

                while (node != NULL) {
                        delta = now - node->first_packet;
                        if (delta > 0) {
                                rps = (unsigned int) ceil(node->count / (float) delta);
                        } else {
                                rps = 0;
                        }

                        if (rps >= rate_threshold) {
                                printf("%s%s%s%s%u rps\n", st_time, FIELD_DELIM, node->host, FIELD_DELIM, rps);
                                prev = node;
                                node = node->next;
                        } else {
                                node = remove_node(node, prev);
                        }
                }
        }

        /* Display rate totals */
        delta = (unsigned int) (now - totals.first_packet);
        if (delta > 0)
                printf("%s%stotals%s%3.2f rps\n", st_time, FIELD_DELIM, FIELD_DELIM, (float) totals.count / delta);

        if (thread_created)
                pthread_mutex_unlock(&stats_lock);

        return;
}

/* Remove the given node from the hash and return it to the free stack;
   returns the correct node for continuing to traverse the hash */
struct host_stats *remove_node(struct host_stats *node, struct host_stats *prev) {
        struct host_stats *next;
        unsigned int hashval;

        /* Unlink the node from the hash */
        if (prev == NULL) {
                hashval = hash_str(node->host, HASHSIZE);

                if (node->next) {
                        stats[hashval] = node->next;
                } else {
                        stats[hashval] = NULL;
                }
                next = stats[hashval];
        } else {
                if (node->next) {
                        prev->next = node->next;
                } else {
                        prev->next = NULL;
                }
                next = prev->next;
        }

        /* Add the node to the head of the free stack */
        node->next = free_stack;
        free_stack = node;

        return next;
}

/* Update the stats for a given host; if the host is not
   found in the hash, add it */
void update_host_stats(char *host, time_t t) {
        struct host_stats *node;
        unsigned int hashval;

        if ((host == NULL) || (stats == NULL)) return;

        if (thread_created)
                pthread_mutex_lock(&stats_lock);

        if ((node = get_host(host)) == NULL) {
                node = get_node();

                hashval = hash_str(host, HASHSIZE);

#ifdef DEBUG
        ASSERT((hashval >= 0) && (hashval < HASHSIZE));
#endif

                str_copy(node->host, host, MAX_HOST_LEN);
                node->count = 0;
                node->first_packet = t;

                /* Link node into hash */
                node->next = stats[hashval];
                stats[hashval] = node;
        }

        if (node->first_packet == 0)
                node->first_packet = t;
        node->last_packet = t;
        node->count++;

        if (totals.first_packet == 0)
                totals.first_packet = t;
        totals.last_packet = t;
        totals.count++;

        if (thread_created)
                pthread_mutex_unlock(&stats_lock);

        return;
}

/* Lookup a particular node in hash; return pointer to node
   if found, NULL otherwise */
struct host_stats *get_host(char *str) {
        struct host_stats *node;

#ifdef DEBUG
        ASSERT(str);
        ASSERT(strlen(str) > 0);
        ASSERT((hash_str(str, HASHSIZE) >= 0) && (hash_str(str, HASHSIZE) < HASHSIZE));
#endif

        for (node = stats[hash_str(str, HASHSIZE)]; node != NULL; node = node->next)
                if (str_compare(str, node->host) == 0)
                        return node;

        return NULL;
}

/* Get a new node from either the free stack or an allocated block;
   if the block is empty, allocate a new chunk of memory */
struct host_stats *get_node() {
        static struct host_stats *block, *tail, **mv;
        struct host_stats *head, **tmp;
        static int alloc_size;

        /* Initialize static variables as necessary */
        if (block_alloc == NULL) {
                block = NULL;
                alloc_size = 0;
        }

        if (free_stack != NULL) { /* Get node from free stack */
                head = free_stack;
                free_stack = free_stack->next;
                head->next = NULL;
        } else if (block != NULL) { /* Get node from allocated block */
                head = block;
                if (block == tail) {
                        block = NULL;
                } else {
                        block++;
                }
        } else { /* Out of nodes, allocate a new block */
                if ((block = (struct host_stats *) malloc(NODE_BLOCKSIZE * sizeof(struct host_stats))) == NULL) {
                        LOG_DIE("Cannot allocate memory for node block");
                }

                /* Store pointer to allocated block so we can free it later */
                if (block_alloc == NULL) {
                        if ((block_alloc = (struct host_stats **) malloc(NODE_ALLOC_BLOCKSIZE * sizeof(struct host_stats *))) == NULL) {
                                LOG_DIE("Cannot allocate memory for blocks array");
                        }

                        mv = block_alloc;
                }

                *mv = block;

                if (++alloc_size % NODE_ALLOC_BLOCKSIZE == 0) {
                        tmp = realloc(block_alloc, ((alloc_size + NODE_ALLOC_BLOCKSIZE) * sizeof(struct host_stats *)));
                        if (tmp == NULL) {
                                LOG_DIE("Cannot re-allocate memory for blocks array");
                        }
                        block_alloc = tmp;
                        mv = block_alloc + alloc_size - 1;
                }

                mv++;
                *mv = NULL;

                tail = block + NODE_BLOCKSIZE - 1;
                head = block;
                block++;
        }

        return head;
}
