/*

  ----------------------------------------------------
  httpry - HTTP logging and information retrieval tool
  ----------------------------------------------------

  Copyright (c) 2005-2007 Jason Bittel <jason.bittel@gmail.com>

*/

#include <ctype.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "error.h"
#include "format.h"

char *strip_whitespace(char *str);
void insert_node(char *str);

typedef struct node NODE;
struct node {
        char *name;
        char *value;
        NODE *next;
};

static NODE *output_fields = NULL;

/* Parse format string to configure output fields */
void parse_format_string(char *str) {
        char *name, *tmp, *i;

        if (strlen(str) == 0)
                LOG_WARN("Empty format string provided");

        /* Make a temporary copy of the string so we don't destroy it */
        if ((tmp = malloc(strlen(str) + 1)) == NULL)
                LOG_DIE("Cannot allocate memory for format string");
        strcpy(tmp, str);

        for (i = tmp; (name = strtok(i, ",")); i = NULL) {
                name = strip_whitespace(name);
                insert_node(name);
        }

        free(tmp);

        return;
}

/* Strip leading and trailing spaces from parameter string */
char *strip_whitespace(char *str) {
        int len;

        while (isspace(*str)) str++;
        len = strlen(str);
        while (len && isspace(*(str + len - 1)))
                *(str + (len--) - 1) = '\0';

        return str;
}

/* Insert a new node at the end of the output format list */
void insert_node(char *name) {
        NODE **node = &output_fields;

        /* Traverse the list while checking for an existing node */
        while (*node) {
                if (strcmp(name, (*node)->name) == 0) {
                        WARN("Format element '%s' already provided", name);

                        return;
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

        return;
}

/* If the node exists, update its value field */
void insert_value(char *name, char *value) {
        NODE *node = output_fields;

        while (node) {
                if (strcmp(name, node->name) == 0) {
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

        if (!output_fields) return;

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

        if (!output_fields) return;

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

        curr = output_fields;
        while (curr) {
                prev = curr;
                curr = curr->next;

                free(prev->name);
                free(prev);
        }

        return;
}
