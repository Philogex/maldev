/* 
array table_of_function_pointers_dynamically_parsed_from_main_as_adjacency_list
var node_count
*/

#ifndef ADJACENCY_TABLE_H
#define ADJACENCY_TABLE_H

// Define the maximum number of nodes in the graph
#define MAX_NODES 9

// Declare the adjacency table (a 2D array) to represent the graph
extern int adj_table[MAX_NODES][MAX_NODES];

// Declare the number of nodes in the graph
extern int node_count;

// Function declarations for nodes
extern void (*nodes[])(void);

#endif // ADJACENCY_TABLE_H