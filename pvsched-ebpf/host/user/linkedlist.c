#include <stdio.h>
#include <stdlib.h>
#include "linkedlist.h"

/*
 * Inputs: data - pointer to the data to store in the node
 * Outputs: Returns a pointer to the newly created Node, or NULL on failure
 * Description: Allocates and initializes a new linked list node
 */
Node *create_node(void *data)
{
	Node *node = (Node *)malloc(sizeof(Node));
	if (!node)
		return NULL;

	node->data = data;
	node->next = NULL;

	return node;
}

/*
 * Inputs: head - double pointer to the head of the linked list
 *         data - pointer to the data to store in the new node
 * Outputs: None
 * Description: Appends a new node with the given data to the end of the linked list
 */
void push_back(Node **head, void *data)
{
	Node *node = create_node(data);

	if (*head == NULL) {
		*head = node;
		return;
	}

	Node *temp = *head;
	while (temp->next != NULL)
		temp = temp->next;

	temp->next = node;
}

/*
 * Inputs: head - pointer to the head of the linked list
 *         print_node - function pointer to a callback that prints the node's data
 * Outputs: None
 * Description: Iterates through the linked list and calls the print_node callback for each element
 */
void print_nodes(Node *head, void (*print_node)(void *))
{
	Node *temp = head;
	while (temp != NULL) {
		print_node(temp->data);
		temp = temp->next;
	}
}