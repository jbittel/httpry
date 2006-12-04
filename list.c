/*

  ----------------------------------------------------
  httpry - HTTP logging and information retrieval tool
  ----------------------------------------------------

  list.c | created: 5/10/2006

  Copyright (c) 2006, Jason Bittel <jbittel@corban.edu>. All rights reserved.

  Redistribution and use in source and binary forms, with or without
  modification, are permitted provided that the following conditions are
  met:

  1. Redistributions of source code must retain the above copyright notice,
     this list of conditions and the following disclaimer.

  2. Redistributions in binary form must reproduce the above copyright notice,
     this list of conditions and the following disclaimer in the documentation
     and/or other materials provided with the distribution.

  3. Neither the name of the author nor the names of its
     contributors may be used to endorse or promote products derived from
     this software without specific prior written permission.

  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS
  IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
  THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
  PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE
  LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
  CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
  SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
  INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
  CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
  ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
  POSSIBILITY OF SUCH DAMAGE.

*/

#include <ctype.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "error.h"
#include "list.h"

/* Create a new node for insertion into an existing list */
NODE *create_node() {
        NODE *list;

        if ((list = (NODE *) malloc(sizeof(NODE))) == NULL) {
                log_die("Cannot allocate memory for new node\n");
        }

        list->name = NULL;
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

/* Update node at the end of list and append a new tail */
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
        if ((list->name = malloc(strlen(str) + 1)) == NULL) {
                log_die("Cannot allocate memory for node name\n");
        }
        strncpy(list->name, str, strlen(str));
        list->name[strlen(str)] = '\0';
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

/* Free all allocated memory for linked list */
void free_list(NODE *list) {
        NODE *prev;
        NODE *curr;

        prev = list;
        if (prev->next == NULL) { /* Empty list */
                free(prev);

                return;
        }

        curr = prev->next;
        while (curr->next != NULL) {
                free(prev->name);
                free(prev);

                prev = curr;
                curr = curr->next;
        }

        free(prev->name);
        free(prev);
        free(curr);

        return;
}
