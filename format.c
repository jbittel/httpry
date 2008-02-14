/*

  ----------------------------------------------------
  httpry - HTTP logging and information retrieval tool
  ----------------------------------------------------

  Copyright (c) 2005-2008 Jason Bittel <jason.bittel@gmail.com>

*/

/*
   Currently the output format string is stored as a hash table 
   with all of the nodes additionally chained together as a linked
   list. This allows insert_value() to utilize the more efficient
   hash structure to find nodes, while print_values() that needs to
   traverse all nodes in insertion order can do so. Functions that
   need to traverse the entire hash can use the linked list as well.

   The hash structure causes some wasted space as the table tends to
   be rather sparse, but the efficiency amortizes nicely on longer
   runs and it scales well to longer format strings.
*/

#include <ctype.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "error.h"
#include "format.h"

#define HASHSIZE 100

typedef struct node NODE;
struct node {
        char *name, *value;
        NODE *next;
};

NODE *insert_node(char *str);
NODE *lookup(char *s);
unsigned hash(char *s);
char *strip_whitespace(char *str);
int strcmp_name(const char *s1, const char *s2);

static NODE *output_fields[HASHSIZE];
static NODE *head = NULL;

/* Parse format string to find and insert output fields */
void parse_format_string(char *str) {
        char *name, *tmp, *i, *c;
        int num_nodes = 0;

#ifdef DEBUG
        ASSERT(str);
#endif

        if (strlen(str) == 0)
                LOG_DIE("Empty format string provided");

        /* Make a temporary copy of the string so we don't modify the original */
        if ((tmp = malloc(strlen(str) + 1)) == NULL)
                LOG_DIE("Cannot allocate memory for format string buffer");
        strcpy(tmp, str);

        for (i = tmp; (name = strtok(i, ",")); i = NULL) {
                /* Normalize input field text */
                name = strip_whitespace(name);
                for (c = name; *c != '\0'; c++) {
                        *c = tolower(*c);
                }

                if (strlen(name) == 0) continue;
                if (insert_node(name)) num_nodes++;
        }

        free(tmp);

        if (num_nodes == 0)
                LOG_DIE("No valid names found in format string");

        return;
}

/* Insert a new node into the hash table */
NODE *insert_node(char *name) {
        NODE *node;
        static NODE *prev = NULL;
        unsigned hashval;

#ifdef DEBUG
        ASSERT(name);
        ASSERT(strlen(name) > 0);
#endif

        if ((node = lookup(name)) == NULL) {
                if ((node = (NODE *) malloc(sizeof(NODE))) == NULL)
                        LOG_DIE("Cannot allocate memory for new node");

                hashval = hash(name);
                node->next = output_fields[hashval];
                output_fields[hashval] = node;
        } else {
                WARN("Format name '%s' already provided", name);
                return NULL;
        }

        if ((node->name = (char *) malloc(strlen(name) + 1)) == NULL)
                LOG_DIE("Cannot allocate memory for node name");
        
        strcpy(node->name, name);
        node->value = NULL;

        /* Update the linked list pointers */
        if (prev) prev->next = node;
        prev = node;
        if (!head) head = node;

        return node;
}

/* If the node exists, update its value field */
void insert_value(char *name, char *value) {
        NODE *node;

#ifdef DEBUG
        ASSERT(output_fields);
        ASSERT(name);
        ASSERT(strlen(name) > 0);
        ASSERT(value);
#endif

        if (strlen(value) == 0) return;

        if ((node = lookup(name)))
                node->value = value;

        return;
}

/* Print a list of all field names contained in the output format */
void print_header_line() {
        NODE *node = head;

#ifdef DEBUG
        ASSERT(output_fields);
#endif

        printf("# Fields: ");
        while (node) {
                printf("%s", node->name);
                if (node->next != NULL) printf(",");

                node = node->next;
        }
        printf("\n");

        return;
}

/* Destructively print each node value; once printed, each existing
   value is assigned to NULL to clear it for the next packet */
void print_values() {
        NODE *node = head;

#ifdef DEBUG
        ASSERT(output_fields);
#endif

        while (node) {
                if (node->value) {
                        printf("%s\t", node->value);
                        node->value = NULL;
                } else {
                        printf("-\t");
                }

                node = node->next;
        }
        printf("\n");

        return;
}

/* Free all allocated memory for format structure; only called at
   program termination */
void free_format() {
        NODE *prev, *curr;

        if (!output_fields) return;

        curr = head;
        while (curr) {
                prev = curr;
                curr = curr->next;

                free(prev->name);
                free(prev);
        }

        return;
}

/* Lookup a particular node in hash; return pointer to node
   if found, NULL otherwise */
NODE *lookup(char *s) {
        NODE *node;

        for (node = output_fields[hash(s)]; node != NULL; node = node->next)
                if (strcmp_name(s, node->name) == 0)
                        return node;

        return NULL;
}

/* Use the djb2 hash function, supposed to be pretty good for strings */
unsigned hash(char *s) {
        unsigned hashval;

        for (hashval = 5381; *s != '\0'; s++)
                hashval = (hashval * 33) ^ *s;

        return hashval % HASHSIZE;
}

/* Strip leading and trailing spaces from parameter string, modifying
   the string in place and returning a pointer to the (potentially)
   new starting point */
char *strip_whitespace(char *str) {
        int len;

#ifdef DEBUG
        ASSERT(str);
        ASSERT(strlen(str) > 0);
#endif

        while (isspace(*str)) str++;
        len = strlen(str);
        while (len && isspace(*(str + len - 1)))
                *(str + (len--) - 1) = '\0';

        return str;
}

/* Function originated as strcasecmp() from the GNU C library; modified
   from its original format since we know s2 will always be lowercase

   Compare s1 and s2, ignoring case of s1, returning less than, equal
   to or greater than zero if s1 is lexiographically less than, equal
   to or greater than s2.  */
int strcmp_name(const char *s1, const char *s2) {
        unsigned char c1, c2;

#ifdef DEBUG
        ASSERT(s1 != s2);
#endif

        do {
                c1 = tolower(*s1++);
                c2 = *s2++;
                if (c1 == '\0') break;
        } while (c1 == c2);

        return c1 - c2;
}
