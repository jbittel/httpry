/*

  ----------------------------------------------------
  httpry - HTTP logging and information retrieval tool
  ----------------------------------------------------

  Copyright (c) 2005-2014 Jason Bittel <jason.bittel@gmail.com>
  Licensed under GPLv2. For further information, see COPYING file.

*/

/*
  The methods data structure is an unbalanced binary tree. All
  packets are checked to see if they have a method contained
  here; any packets that do not will be ignored.

  This doesn't use a hash because the length of the potential
  method is not known. At this point in the main processing
  loop the packet data is still in a static buffer, so this
  gives us a simpler solution. Perhaps at some point the flow
  of the packet processing will be changed and we can switch
  to a more traditional lookup table approach.
*/

#include <ctype.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "error.h"
#include "methods.h"
#include "utility.h"

typedef struct method_node METHOD_NODE;
struct method_node {
        char *method;
        METHOD_NODE *left, *right;
};

static METHOD_NODE *methods = NULL;

int insert_method(char *str, size_t len);
void free_node(METHOD_NODE *node);

/* Parse and insert methods from methods string */
void parse_methods_string(char *str) {
        char *method, *tmp, *i;
        int num_methods = 0;
        size_t len;

#ifdef DEBUG
        ASSERT(str);
#endif
        len = strlen(str);
        if (len == 0)
                LOG_DIE("Empty methods string provided");

        /* Make a temporary copy of the string so we don't modify the original */
        if ((tmp = str_duplicate(str)) == NULL)
                LOG_DIE("Cannot allocate memory for methods string buffer");

        for (i = tmp; (method = strtok(i, ",")); i = NULL) {
                method = str_strip_whitespace(method);
                method = str_tolower(method);
                len = strlen(method);

                if (len == 0) continue;
                if (insert_method(method, len)) num_methods++;
        }

        free(tmp);

        if (num_methods == 0)
                LOG_DIE("No valid methods found in string");

        return;
}

/* Insert a new method into the structure */
int insert_method(char *method, size_t len) {
        METHOD_NODE **node = &methods;
        int cmp;

#ifdef DEBUG
        ASSERT(method);
        ASSERT(strlen(method) > 0);
#endif

        while (*node) {
                cmp = str_compare(method, (*node)->method);
                if (cmp > 0) {
                        node = &(*node)->right;
                } else if (cmp < 0) {
                        node = &(*node)->left;
                } else {
                        WARN("Method '%s' already provided", method);

                        return 0;
                }
        }

        if ((*node = (METHOD_NODE *) malloc(sizeof(METHOD_NODE))) == NULL) {
                LOG_DIE("Cannot allocate memory for method node");
        }

        if (((*node)->method = (char *) malloc(len + 1)) == NULL) {
                LOG_DIE("Cannot allocate memory for method string");
        }
        str_copy((*node)->method, method, len + 1);

        (*node)->left = (*node)->right = NULL;

        return 1;
}

/* Search data structure for a matching method */
int is_request_method(const char *str) {
        METHOD_NODE *node = methods;
        int cmp;

#ifdef DEBUG
        ASSERT(node);
        ASSERT(str);
#endif

        if (strlen(str) == 0) return 0;

        while (node) {
                cmp = str_compare(str, node->method);
                if (cmp > 0) {
                        node = node->right;
                } else if (cmp < 0) {
                        node = node->left;
                } else {
                        return 1;
                }
        }

        return 0;
}

/* Wrapper function to free allocated memory at program termination */
void free_methods() {
        free_node(methods);

        return;
}

/* Recursively free all children of the parameter node */
void free_node(METHOD_NODE *node) {
        if (!node) return;

        free_node(node->left);
        free_node(node->right);

        free(node->method);
        free(node);

        return;
}
