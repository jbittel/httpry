/*

  ----------------------------------------------------
  httpry - HTTP logging and information retrieval tool
  ----------------------------------------------------

  Copyright (c) 2005-2007 Jason Bittel <jason.bittel@gmail.com>

*/

#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "error.h"
#include "list.h"

typedef struct node NODE;
struct node {
        char *name;
        char *value;
        NODE *next;
};

static NODE *output_fields = NULL;

/* Insert a new node onto the tail of the output format list */
void insert_node(char *str) {
        NODE **node = &output_fields;

        /* Go to end of list, checking for existing node on the way */
        while (*node) {
                if (strcmp(str, (*node)->name) == 0) {
                        WARN("Format element '%s' already provided", (*node)->name);

                        return;
                }

                node = &(*node)->next;
        }

        /* Create a new node and append it to the list */
        if (((*node) = (NODE *) malloc(sizeof(NODE))) == NULL) {
                LOG_DIE("Cannot allocate memory for new node");
        }

        if (((*node)->name = malloc(strlen(str) + 1)) == NULL) {
                LOG_DIE("Cannot allocate memory for node name");
        }
        
        strcpy((*node)->name, str);
        (*node)->value = NULL;
        (*node)->next = NULL;

        return;
}

/* If the node exists, update its value field */
void insert_value(char *str, char *value) {
        NODE *node = output_fields;

        while (node) {
                if (strcmp(str, node->name) == 0) {
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
void print_list() {
        NODE *node = output_fields;

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

/* Free all allocated memory for linked list; only
   called at program termination */
void free_list() {
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
