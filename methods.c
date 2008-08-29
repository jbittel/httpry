/*

  ----------------------------------------------------
  httpry - HTTP logging and information retrieval tool
  ----------------------------------------------------

  Copyright (c) 2005-2008 Jason Bittel <jason.bittel@gmail.com>

*/

/*
*/

#include <ctype.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "error.h"
#include "methods.h"
#include "utility.h"

#define HASHSIZE 20

typedef struct node NODE;
struct node {
        char *name;
        NODE *next, *list;
};

static NODE *methods[HASHSIZE];
static NODE *head = NULL;

NODE *insert_method(char *str);
void free_node(NODE *node);
NODE *method_lookup(const char *str, int len);
unsigned hash_method_string(const char *str, int len);
void free_methods();

/* Parse and insert methods from input string */
void parse_methods_string(char *str) {
        char *method, *tmp, *i;
        int num_methods = 0;

#ifdef DEBUG
        ASSERT(str);
#endif

        if (strlen(str) == 0)
                LOG_DIE("Empty methods string provided");

        /* Make a temporary copy of the string so we don't modify the original */
        if ((tmp = malloc(strlen(str) + 1)) == NULL)
                LOG_DIE("Cannot allocate memory for methods string buffer");
        strcpy(tmp, str);

        for (i = tmp; (method = strtok(i, ",")); i = NULL) {
                method = str_strip_whitespace(method);
                method = str_tolower(method);

                if (strlen(method) == 0) continue;
                if (insert_method(method)) num_methods++;
        }

        free(tmp);

        if (num_methods == 0)
                LOG_DIE("No valid methods found in string");

#ifdef DEBUG
        int j, num_buckets = 0, num_chain, max_chain = 0;
        NODE *node;

        for (j = 0; j < HASHSIZE; j++) {
                if (methods[j]) num_buckets++;

                num_chain = 0;
                for (node = methods[j]; node != NULL; node = node->next) num_chain++;
                if (num_chain > max_chain) max_chain = num_chain;
        }

        PRINT("----------------------------");
        PRINT("Hash buckets:       %d", HASHSIZE);
        PRINT("Nodes inserted:     %d", num_methods);
        PRINT("Buckets in use:     %d", num_buckets);
        PRINT("Hash collisions:    %d", num_methods - num_buckets);
        PRINT("Longest hash chain: %d", max_chain);
        PRINT("----------------------------");
#endif

        return;
}

/* Insert a new method into the structure */
NODE *insert_method(char *method) {
        NODE *node;
        static NODE *prev = NULL;
        unsigned hashval;

#ifdef DEBUG
        ASSERT(method);
        ASSERT(strlen(method) > 0);
#endif
 
        if ((node = method_lookup(method, strlen(method))) == NULL) {
                if ((node = (NODE *) malloc(sizeof(NODE))) == NULL)
                        LOG_DIE("Cannot allocate memory for method node");

                hashval = hash_method_string(method, strlen(method));

#ifdef DEBUG
        ASSERT((hashval >= 0) && (hashval < HASHSIZE));
#endif

                node->next = methods[hashval];
                methods[hashval] = node;
        } else {
                WARN("Method '%s' already provided", method);
                return NULL;
        }

        if ((node->name = (char *) malloc(strlen(method) + 1)) == NULL) {
                LOG_DIE("Cannot allocate memory for method string");
        }
        strcpy(node->name, method);

        /* Update the linked list pointers */
        if (prev) prev->list = node;
        prev = node;
        if (!head) head = node;

        return node;
}

/* Search parameter string for a matching method */
int is_request_method(const char *str) {
        NODE *node;
        int len;
        char *c;

#ifdef DEBUG
        ASSERT(str);
#endif

        if (strlen(str) == 0) return 0;

        c = strchr(str, ' ');
        if (!c) return 0;
        len = c - str;

        if ((node = method_lookup(str, len))) return 1;

        return 0;
}

/* Lookup a particular node in hash; return pointer to node
   if found, NULL otherwise */
NODE *method_lookup(const char *str, int len) {
        NODE *node;

#ifdef DEBUG
        ASSERT(str);
        ASSERT(strlen(str) > 0);
        ASSERT(len);
        ASSERT((hash_method_string(str, len) >= 0) && (hash_method_string(str, len) < HASHSIZE));
#endif

        for (node = methods[hash_method_string(str, len)]; node != NULL; node = node->next)
                if (str_compare(str, node->name, strlen(node->name)) == 0)
                        return node;

        return NULL;
}

/* Use the djb2 hash function; supposed to be good for strings */
unsigned hash_method_string(const char *str, int len) {
        unsigned hashval;

#ifdef DEBUG
        ASSERT(str);
        ASSERT(strlen(str) > 0);
        ASSERT(len);
#endif

        for (hashval = 5381; (--len > 0) && (*str != '\0'); str++)
                hashval = (hashval * 33) ^ tolower(*str);

        return hashval % HASHSIZE;
}

/* Free all allocated memory for methods; only called at program termination */
void free_methods() {
        NODE *prev, *curr;

        if (!head) return;

        curr = head;
        while (curr) {
                prev = curr;
                curr = curr->list;

                free(prev->name);
                free(prev);
        }

        return;
}
