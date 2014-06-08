/*

  ----------------------------------------------------
  httpry - HTTP logging and information retrieval tool
  ----------------------------------------------------

  Copyright (c) 2005-2014 Jason Bittel <jason.bittel@gmail.com>
  Licensed under GPLv2. For further information, see COPYING file.

*/

/*
  The output format data structure is stored as a hash table
  with all of the nodes additionally chained together as a linked
  list. This allows insert_value() to utilize the more efficient
  hash structure to find nodes, while functions that need to
  traverse all nodes in insertion order can use the linked list.
  A separate head pointer is maintained for the start of the
  linked list.

  The hash table creates some wasted space as the table tends to
  be rather sparse, but the efficiency amortizes on longer runs
  and it scales well to longer format strings.
*/

#include <ctype.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/types.h>
#include "error.h"
#include "format.h"
#include "utility.h"

#define HASHSIZE 64

typedef struct format_node FORMAT_NODE;
struct format_node {
        char *name, *value;
        FORMAT_NODE *next, *list;
};

FORMAT_NODE *insert_field(char *str, size_t len);
FORMAT_NODE *get_field(char *str);

static FORMAT_NODE *fields[HASHSIZE];
static FORMAT_NODE *head = NULL;

/* Parse and insert output fields from format string */
void parse_format_string(char *str) {
        char *name, *tmp, *i;
        int num_nodes = 0;
        size_t len;

#ifdef DEBUG
        ASSERT(str);
#endif

        len = strlen(str);
        if (len == 0)
                LOG_DIE("Empty format string provided");

        /* Make a temporary copy of the string so we don't modify the original */
        if ((tmp = str_duplicate(str)) == NULL)
                LOG_DIE("Cannot allocate memory for format string buffer");

        for (i = tmp; (name = strtok(i, ",")); i = NULL) {
                /* Normalize input field text */
                name = str_strip_whitespace(name);
                name = str_tolower(name);
                len = strlen(name);

                if (len == 0) continue;
                if (insert_field(name, len)) num_nodes++;
        }

        free(tmp);

        if (num_nodes == 0)
                LOG_DIE("No valid fields found in format string");

#ifdef DEBUG
        int j, num_buckets = 0, num_chain, max_chain = 0;
        FORMAT_NODE *node;

        for (j = 0; j < HASHSIZE; j++) {
                if (fields[j]) num_buckets++;

                num_chain = 0;
                for (node = fields[j]; node != NULL; node = node->next) num_chain++;
                if (num_chain > max_chain) max_chain = num_chain;
        }

        PRINT("----------------------------");
        PRINT("Hash buckets:       %d", HASHSIZE);
        PRINT("Nodes inserted:     %d", num_nodes);
        PRINT("Buckets in use:     %d", num_buckets);
        PRINT("Hash collisions:    %d", num_nodes - num_buckets);
        PRINT("Longest hash chain: %d", max_chain);
        PRINT("----------------------------");
#endif

        return;
}

/* Insert a new node into the hash table */
FORMAT_NODE *insert_field(char *name, size_t len) {
        FORMAT_NODE *node;
        static FORMAT_NODE *prev = NULL;
        unsigned int hashval;

#ifdef DEBUG
        ASSERT(name);
        ASSERT(len > 0);
#endif

        if ((node = get_field(name)) == NULL) {
                if ((node = (FORMAT_NODE *) malloc(sizeof(FORMAT_NODE))) == NULL)
                        LOG_DIE("Cannot allocate memory for new node");

                hashval = hash_str(name, HASHSIZE);

#ifdef DEBUG
        ASSERT((hashval >= 0) && (hashval < HASHSIZE));
#endif

                node->next = fields[hashval];
                fields[hashval] = node;
        } else {
                WARN("Format name '%s' already provided", name);
                return NULL;
        }

        if ((node->name = (char *) malloc(len + 1)) == NULL)
                LOG_DIE("Cannot allocate memory for node name");
        str_copy(node->name, name, len + 1);

        node->value = NULL;
        node->list = NULL;

        /* Update the linked list pointers */
        if (prev) prev->list = node;
        prev = node;
        if (!head) head = node;

        return node;
}

/* If the node exists, update its value field */
void insert_value(char *name, char *value) {
        FORMAT_NODE *node;

#ifdef DEBUG
        ASSERT(name);
        ASSERT(value);
#endif

        if ((strlen(name) == 0) || (strlen(value) == 0))
                return;

        if ((node = get_field(name)))
                node->value = value;

        return;
}

/* Given the name, return a value from the hash */
char *get_value(char *name) {
        FORMAT_NODE *node;

#ifdef DEBUG
        ASSERT(name);
#endif

        if (strlen(name) == 0)
                return EMPTY_FIELD;

        if ((node = get_field(name))) {
                return node->value;
        } else {
                return EMPTY_FIELD;
        }
}

void clear_values() {
        FORMAT_NODE *node = head;

#ifdef DEBUG
        ASSERT(node);
#endif

        while (node) {
                node->value = NULL;
                node = node->list;
        }

        return;
}

/* Print a list of all field names contained in the output format */
void print_format_list() {
        FORMAT_NODE *node = head;

#ifdef DEBUG
        ASSERT(node);
#endif

        printf("# Fields: ");
        while (node) {
                printf("%s", node->name);
                if (node->list != NULL) printf(",");

                node = node->list;
        }
        printf("\n");

        return;
}

/* Destructively print each node value; once printed, each existing
   value is assigned to NULL to clear it for the next packet */
void print_format_values() {
        FORMAT_NODE *node = head;

#ifdef DEBUG
        ASSERT(node);
#endif

        while (node) {
                if (node->value) {
                        printf("%s", node->value);
                        node->value = NULL;
                } else {
                        printf("%s", EMPTY_FIELD);
                }

                if (node->list != NULL)
                        printf("%s", FIELD_DELIM);

                node = node->list;
        }
        printf("\n");

        return;
}

/* Free all allocated memory for format structure; only called at
   program termination */
void free_format() {
        FORMAT_NODE *prev, *curr;

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

/* Lookup a particular node in hash; return pointer to node
   if found, NULL otherwise */
FORMAT_NODE *get_field(char *str) {
        FORMAT_NODE *node;

#ifdef DEBUG
        ASSERT(str);
        ASSERT(strlen(str) > 0);
        ASSERT((hash_str(str, HASHSIZE) >= 0) && (hash_str(str, HASHSIZE) < HASHSIZE));
#endif

        for (node = fields[hash_str(str, HASHSIZE)]; node != NULL; node = node->next)
                if (str_compare(str, node->name) == 0)
                        return node;

        return NULL;
}
