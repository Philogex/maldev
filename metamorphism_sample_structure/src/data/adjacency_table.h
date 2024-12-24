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

// Function declarations for nodes (they could be inlined in the main for simplicity)
extern void node_0();
extern void node_1();
extern void node_2();
extern void node_3();
extern void node_4();
extern void node_5();
extern void node_6();
extern void node_7();
extern void node_8();

#endif // ADJACENCY_TABLE_H
