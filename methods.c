/*

  ----------------------------------------------------
  httpry - HTTP logging and information retrieval tool
  ----------------------------------------------------

  Copyright (c) 2005-2008 Jason Bittel <jason.bittel@gmail.com>

*/

/*
  The methods data structure is a binary tree. All packets are
  checked to see if they have a method contained here; any
  packets that do not will be ignored.
 
  The tree is built as an unbalanced binary tree. Once created,
  each search of the tree checks the depth at which each node is
  found. If the node is located and is below a specific depth,
  the tree is splayed to put the node at the root of the tree.
  This keeps the tree optimized for lookups, while limiting the
  number of splay operations performed.

  The splay() function code was originally obtained from:
     http://www.link.cs.cmu.edu/link/ftp-site/splaying/top-down-splay.c
  
  Many alterations and modifications have been made to the
  original code.
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

int insert_method(char *str);
METHOD_NODE *splay(const char *method, METHOD_NODE *t);
int print_tree(METHOD_NODE *node, int depth);
void free_node(METHOD_NODE *node);

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
        
        print_tree(methods, 0);

/*#ifdef DEBUG
        int methods_cnt = 0;
        int max_depth = 0;
        int balance = 0;

        PRINT("----------------------------");
        PRINT("Methods inserted:   %d", methods_cnt);
        PRINT("Max depth:          %d", max_depth);
        PRINT("Tree balance:       %d%%", balance);
        PRINT("----------------------------");
#endif*/

        return;
}

/* Insert a new method into the structure */
int insert_method(char *method) {
        METHOD_NODE **node = &methods;
        int cmp;

#ifdef DEBUG
        ASSERT(method);
        ASSERT(strlen(method) > 0);
#endif
        
        while (*node) {
                cmp = str_compare(method, (*node)->method, strlen((*node)->method));
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
        
        if (((*node)->method = (char *) malloc(strlen(method) + 1)) == NULL) {
                LOG_DIE("Cannot allocate memory for method string");
        }
        
        strcpy((*node)->method, method);
        (*node)->left = (*node)->right = NULL;

        return 1;
}

/* Search parameter string for a matching method */
int is_request_method(const char *str) {
        METHOD_NODE *node = methods;
        int cmp, depth = 0;

#ifdef DEBUG
        ASSERT(str);
#endif

        if (strlen(str) == 0) return 0;

        while (node) {
                depth++;
                cmp = str_compare(str, node->method, strlen(node->method));
                if (cmp > 0) {
                        node = node->right;
                } else if (cmp < 0) {
                        node = node->left;
                } else {
                        PRINT("Found node at depth %d", depth);
                        if (depth > 2)
                                methods = splay(str, methods);

                        return 1;
                }
        }

        return 0;
}

/* Search for specified method in tree rooted at t */
METHOD_NODE *splay(const char *method, METHOD_NODE *t) {
        METHOD_NODE N, *l, *r, *y;
        int cmp;

#ifdef DEBUG
        ASSERT(method);
        ASSERT(strlen(method) > 0);
        ASSERT(t);
#endif
        
        N.left = N.right = NULL;
        l = r = &N;

        for (;;) {
                cmp = str_compare(method, t->method, strlen(method));
                if (cmp < 0) {
                        if (t->left == NULL) break;
                        if (str_compare(method, t->left->method, strlen(method)) < 0) {
                                PRINT("Rotating right"); 
                                y = t->left;
                                t->left = y->right;
                                y->right = t;
                                t = y;
                                if (t->left == NULL) break;
                        }
                        PRINT("Linking right");
                        r->left = t;
                        r = t;
                        t = t->left;
                } else if (cmp > 0) {
                        if (t->right == NULL) break;
                        if (str_compare(method, t->right->method, strlen(method)) > 0) {
                                PRINT("Rotating left");
                                y = t->right;
                                t->right = y->left;
                                y->left = t;
                                t = y;
                                if (t->right == NULL) break;
                        }
                        PRINT("Linking left");
                        l->right = t;
                        l = t;
                        t = t->right;
                } else {
                        PRINT("Matched node");
                        break;
                }
        }
        
        PRINT("Assembling");
        l->right = t->left;
        r->left = t->right;
        t->left = N.right;
        t->right = N.left;
        
        print_tree(t, 0);
        
        return t;
}

int print_tree(METHOD_NODE *node, int depth) {
        if (!node) return depth;
        
        print_tree(node->left, ++depth);
        PRINT("method: %s at depth %d", node->method, depth);
        print_tree(node->right, ++depth);
        
        return --depth;
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
