#include "adjacency_table.h"
#include <stdio.h>

// Define the adjacency table... this is more like a matrix, but okay
int adj_table[MAX_NODES][MAX_NODES] = {
    // i can defined static edges in here if i implement the functionality, since it always uses this as a base. i can make these already be connected or set precedence for example
};

// Define the number of nodes
int node_count = MAX_NODES;

// Define the functions for each node
__attribute__((annotate("encrypt")))
void node_0() {
    printf("Hello from Node 0!\n");
}

__attribute__((annotate("encrypt")))
void node_1() {
    printf("Hello from Node 1!\n");
}

__attribute__((annotate("encrypt")))
void node_2() {
    printf("Hello from Node 2!\n");
}

__attribute__((annotate("encrypt")))
void node_3() {
    printf("Hello from Node 3!\n");
}

__attribute__((annotate("encrypt")))
void node_4() {
    printf("Hello from Node 4!\n");
}

__attribute__((annotate("encrypt")))
void node_5() {
    printf("Hello from Node 5!\n");
}

__attribute__((annotate("encrypt")))
void node_6() {
    printf("Hello from Node 6!\n");
}

__attribute__((annotate("encrypt")))
void node_7() {
    printf("Hello from Node 7!\n");
}

__attribute__((annotate("encrypt")))
void node_8() {
    printf("Hello from Node 8!\n");
}

void (*nodes[])(void) = {node_0, node_1, node_2, node_3, node_4, node_5, node_6, node_7, node_8};