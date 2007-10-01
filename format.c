/*

  ----------------------------------------------------
  httpry - HTTP logging and information retrieval tool
  ----------------------------------------------------

  Copyright (c) 2005-2007 Jason Bittel <jason.bittel@gmail.com>

*/

/*
   Currently the output format string is stored as a binary tree
   with all of the nodes additionally chained together as a linked
   list. This allows insert_value() to utilize the more efficient
   tree structure to find nodes, while print_values() that needs to
   traverse all nodes in insertion order can do so. Functions that
   need to traverse the entire tree can use the linked list as well,
   so as to avoid recursion. The tree structure should help this
   scale relatively well to longer format strings.

   TODO: We could squeeze out a litte more efficiency if we implement
   this as a balanced binary tree. Right now, worst case behavior
   means the whole thing behaves as a linked list, which is how it
   was implemented previously anyway. In the future we should convert
   this, since a _lot_ of time is spent searching the tree.
*/

#include <ctype.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "error.h"
#include "format.h"

char *strip_whitespace(char *str);
int insert_name(char *str);
int strcmp_name(const char *s1, const char *s2);

typedef struct node NODE;
struct node {
        char *name, *value;
        NODE *left, *right, *next;
};

/* Head of tree/list structure storing name/value pairs */
static NODE *output_fields = NULL;

/* Parse format string to configure output fields */
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
                if (insert_name(name) == 1) num_nodes++;
        }

        free(tmp);

        if (num_nodes == 0)
                LOG_DIE("No valid names found in format string");

        return;
}

/* Insert a new node into the format tree structure */
int insert_name(char *name) {
        NODE **node = &output_fields;
        static NODE *prev = NULL;
        int cmp;

#ifdef DEBUG
        ASSERT(name);
        ASSERT(strlen(name) > 0);
#endif

        /* Find the insertion point while checking for an existing node */
        while (*node) {
                cmp = strcmp_name(name, (*node)->name);
                if (cmp > 0) {
                        node = &(*node)->right;
                } else if (cmp < 0) {
                        node = &(*node)->left;
                } else {
                        WARN("Format name '%s' already provided", name);

                        return 0;
                }
        }

        /* No node found so create a new one */
        if (((*node) = (NODE *) malloc(sizeof(NODE))) == NULL)
                LOG_DIE("Cannot allocate memory for new node");

        if (((*node)->name = (char *) malloc(strlen(name) + 1)) == NULL)
                LOG_DIE("Cannot allocate memory for node name");
        
        strcpy((*node)->name, name);
        (*node)->value = NULL;
        (*node)->left = (*node)->right = (*node)->next = NULL;

        /* Update the linked list pointers within the tree */
        if (prev) prev->next = (*node);
        prev = (*node);

        return 1;
}

/* If the node exists, update its value field */
void insert_value(char *name, char *value) {
        NODE *node = output_fields;
        int cmp;

#ifdef DEBUG
        ASSERT(output_fields);
        ASSERT(name);
        ASSERT(strlen(name) > 0);
        ASSERT(value);
#endif

        if (strlen(value) == 0) return;

        while (node) {
                cmp = strcmp_name(name, node->name);
                if (cmp > 0) {
                        node = node->right;
                } else if (cmp < 0) {
                        node = node->left;
                } else {
                        node->value = value;

                        return;
                }
        }

        return;
}

/* Print a list of all field names contained in the format structure */
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

/* Destructively print each node value; once printed, each existing
   value is assigned to NULL to clear it for the next packet */
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
