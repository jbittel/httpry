/*

  ----------------------------------------------------
  httpry - HTTP logging and information retrieval tool
  ----------------------------------------------------

  Copyright (c) 2005-2008 Jason Bittel <jason.bittel@gmail.com>

*/

/*
  The methods data structure is an unbalanced binary tree. All
  packets are checked to see if they have a method contained
  here; any packets that do not will be ignored.
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
METHOD_NODE *insert_splay(char *method, METHOD_NODE *t);
METHOD_NODE *splay(char *method, METHOD_NODE *t);
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
                /*if (insert_method(method)) num_methods++;*/
                /*if (insert_splay(method, methods)) num_methods++;*/
                methods = insert_splay(method, methods);
        }

        free(tmp);

        /*if (num_methods == 0)
                LOG_DIE("No valid methods found in string");*/

#ifdef DEBUG
        int methods_cnt = 0;
        int max_depth = 0;
        int balance = 0;

        /* TODO: non-recursive tree traversal to calculate these values */

        PRINT("----------------------------");
        PRINT("Methods inserted:   %d", methods_cnt);
        PRINT("Max depth:          %d", max_depth);
        PRINT("Tree balance:       %d%%", balance);
        PRINT("----------------------------");
#endif

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

METHOD_NODE *insert_splay(char *method, METHOD_NODE *t) {
        METHOD_NODE *new;
        int cmp;
        
        if ((new = (METHOD_NODE *) malloc(sizeof(METHOD_NODE))) == NULL) {
                LOG_DIE("Cannot allocate memory for method node");
        }
        
        if ((new->method = (char *) malloc(strlen(method) + 1)) == NULL) {
                LOG_DIE("Cannot allocate memory for method string");
        }
        
        strcpy(new->method, method);
        
        if (t == NULL) {
                new->left = new->right = NULL;

                return new;
        }
        
        t = splay(method, t);
        
        cmp = str_compare(method, t->method, strlen(t->method));
        if (cmp < 0) {
                new->left = t->left;
                new->right = t;
                t->left = NULL;
                
                return new;
        } else if (cmp > 0) {
                new->right = t->right;
                new->left = t;
                t->right = NULL;
                
                return new;
        } else {
                free(new->method);
                free(new);
                
                return t;
        }
}

METHOD_NODE *splay(char *method, METHOD_NODE *t) {
        METHOD_NODE N, *l, *r, *y;
        int cmp;
        
        if (t == NULL) return t;
        
        N.left = N.right = NULL;
        l = r = &N;
        
        for (;;) {
                cmp = str_compare(method, t->method, strlen(t->method));
                if (cmp < 0) {
                        if (t->left == NULL) break;
                        if (str_compare(method, t->left->method, strlen(method)) < 0) {
                                y = t->left;
                                t->left = y->right;
                                y->right = t;
                                t = y;
                                if (t->left == NULL) break;
                        }
                        r->left = t;
                        r = t;
                        t = t->left;
                } else if (cmp > 0) {
                        if (t->right == NULL) break;
                        if (str_compare(method, t->right->method, strlen(method)) > 0) {
                                y = t->right;
                                t->right = y->left;
                                y->left = t;
                                t = y;
                                if (t->right == NULL) break;
                        }
                        l->right = t;
                        l = t;
                        t = t->right;
                } else {
                        break;
                }
        }
        
        l->right = t->left;
        r->left = t->right;
        t->left = N.right;
        t->right = N.left;
        
        return t;
}

/* Search parameter string for a matching method */
int is_request_method(const char *str) {
        /*METHOD_NODE *node = methods;*/

#ifdef DEBUG
        ASSERT(str);
#endif

        if (strlen(str) == 0) return 0;
        
/*        while (node) {
                cmp = str_compare(str, node->method, strlen(node->method));
                if (cmp > 0) {
                        node = node->right;
                } else if (cmp < 0) {
                        node = node->left;
                } else {
                        return 1;
                }
        }

        return 0;*/
        
        methods = splay(str, methods);
        if (str_compare(str, methods->method, strlen(methods->method)) == 0) {
                return 1;
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
