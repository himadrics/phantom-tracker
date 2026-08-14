#ifndef LINKEDLIST_H
#define LINKEDLIST_H
/* Node definition */

typedef struct Node {
	struct vcpu_t *data;
	struct Node *next;
} Node;
Node *create_node(void *data);

void push_back(Node **head, void *data);

void print_nodes(Node *head, void (*print_node)(void *));
#endif