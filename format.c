/*

  ----------------------------------------------------
  httpry - HTTP logging and information retrieval tool
  ----------------------------------------------------

  Copyright (c) 2005-2007 Jason Bittel <jason.bittel@gmail.com>

*/

/* Currently the output format string is stored as a linked list
   with each node containing the field name and associated value.
   This maintains proper ordering of the fields and is relatively
   fast inserting/printing for formats of a reasonable length.

   TODO: it might be beneficial to store the values in a hash and
   merely use this linked list for printing the entire string. That
   way insert_value() could be called in O(1) time and output
   ordering would be maintained. The downsides to this would be the
   additional complexity, and potentially worse behavior with a
   bad hash function and/or data (although it probably wouldn't get
   significantly more expensive than it currently is). */

#include <ctype.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "error.h"
#include "format.h"

char *strip_whitespace(char *str);
int insert_node(char *str);
int strcmp_name(const char *s1, const char *s2);

typedef struct node NODE;
struct node {
        char *name;
        char *value;
        NODE *next;
};

/* Head of linked list storing name/value pairs */
static NODE *output_fields = NULL;

/* Parse format string to configure output fields */
void parse_format_string(char *str) {
        char *name, *tmp, *i;
        int num_nodes = 0;
        unsigned char *c;

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
                if (insert_node(name) == 1) num_nodes++;
        }

        free(tmp);

        if (num_nodes == 0)
                LOG_DIE("No valid names found in format string");

        return;
}

/* Insert a new node at the end of the output format list */
int insert_node(char *name) {
        NODE **node = &output_fields;

#ifdef DEBUG
        ASSERT(name);
        ASSERT(strlen(name) > 0);
#endif

        /* Traverse the list while checking for an existing node */
        while (*node) {
                if (strcmp_name(name, (*node)->name) == 0) {
                        WARN("Format name '%s' already provided", name);

                        return 0;
                }

                node = &(*node)->next;
        }

        /* Create a new node and append it to the list */
        if (((*node) = (NODE *) malloc(sizeof(NODE))) == NULL)
                LOG_DIE("Cannot allocate memory for new node");

        if (((*node)->name = malloc(strlen(name) + 1)) == NULL)
                LOG_DIE("Cannot allocate memory for node name");
        
        strcpy((*node)->name, name);
        (*node)->value = NULL;
        (*node)->next = NULL;

        return 1;
}

/* If the node exists, update its value field */
void insert_value(char *name, char *value) {
        NODE *node = output_fields;

#ifdef DEBUG
        ASSERT(output_fields);
        ASSERT(name);
        ASSERT(value);
#endif

        /* Abort if string is empty */
        if (strlen(value) == 0) return;

        while (node) {
                if (strcmp_name(name, node->name) == 0) {
                        node->value = value;

                        return;
                }

                node = node->next;
        }

        return;
}

/* Print a list of all output field names contained in the format string */
void print_header_line() {
        NODE *node = output_fields;

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

/* Destructively print each node value in the list; once printed, each
   existing value is assigned to NULL to clear it for the next packet */
void print_values() {
        NODE *node = output_fields;

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

        curr = output_fields;
        while (curr) {
                prev = curr;
                curr = curr->next;

                free(prev->name);
                free(prev);
        }

        return;
}

/* Strip leading and trailing spaces from parameter string, modifying
   the string in place and returning a pointer to the (potentially)
   new starting point */
char *strip_whitespace(char *str) {
        int len;

#ifdef DEBUG
        ASSERT(str);
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
