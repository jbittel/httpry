/*

  ----------------------------------------------------
  httpry - HTTP logging and information retrieval tool
  ----------------------------------------------------

  list.c 5/10/2006

  Copyright (c) 2006, Jason Bittel <jbittel@corban.edu>. All rights reserved.
  See included LICENSE file for specific licensing information

*/

#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "list.h"

/* Create a new node for insertion into an existing list */
NODE *create_node() {
        NODE *list;

        if ((list = (NODE *) malloc(sizeof(NODE))) == NULL) {
                /*log_die("Cannot malloc memory for new node");*/
                return NULL;
        }

        list->name[0] = '\0';
        list->value = NULL;
        list->next = NULL;

        return list;
}

/* Check to see if a node with the given name exists in the list */
NODE *find_node(NODE *list, char *str) {
        while (list->next != NULL) {
                if (strcmp(str, list->name) == 0) {
                        return list;
                }

                list = list->next;
        }

        return NULL;
}

/* Insert a new unique node at the end of the list and append a new tail */
int insert_node(NODE *list, char *str) {
        NODE *tail;
        
        if (find_node(list, str) != NULL) {
                return 0; /* A node with that name already exists */
        }

        /* Find tail of list */
        while (list->next != NULL) {
                list = list->next;
        }

        /* Create new list tail */
        tail = create_node();
       
        /* Populate node with new data */
        strncpy(list->name, str, strlen(str));
        list->value = NULL;
        list->next = tail;

        return 1;
}

/* Destructively print each node value in the list; once printed, each
   existing value is assigned to NULL to clear it for the next packet */
void print_list(NODE *list) {
        while (list->next != NULL) {
                if (list->value != NULL) {
                        printf("%s\t", list->value);
                        list->value = NULL;
                } else {
                        printf("-\t");
                }

                list = list->next;
        }
        printf("\n");

        return;
}
