/*

  ----------------------------------------------------
  httpry - HTTP logging and information retrieval tool
  ----------------------------------------------------

  list.h 5/10/2006

  Copyright (c) 2006, Jason Bittel <jbittel@corban.edu>. All rights reserved.
  See included LICENSE file for specific licensing information

*/

typedef struct node NODE;
struct node {
        char name[30];
        char *value;
        NODE *next;
};

NODE *create_node();
NODE *find_node(NODE *list, char *str);
int insert_node(NODE *list, char *str);
void print_list(NODE *list);
