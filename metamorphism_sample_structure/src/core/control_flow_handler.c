/*
func reorder_edges (using prng to generate directed acyclic graph)
func execute_graph
*/

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include "control_flow_handler.h"

// Function to reorder edges and ensure connectivity by adding random edges
void reorder_edges(int (*adj_matrix)[MAX_NODES][MAX_NODES]) {
    srand(prng_seed);  // Seed the random number generator

    // List of connected nodes
    int connected[MAX_NODES] = {0};
    int connected_count = 1;  // Start with the first node as connected
    connected[0] = 1;         // Mark node 0 as connected

    // Start connecting nodes
    while (connected_count < node_count) {
        // Randomly select an unconnected node
        int unconnected_node = rand() % node_count;

        // Ensure the node is unconnected
        while (connected[unconnected_node] == 1) {
            unconnected_node = rand() % node_count;  // Choose again if already connected
        }

        // Randomly choose a connected node
        int connected_node = rand() % node_count;

        // Ensure the selected connected node is actually connected
        while (connected[connected_node] == 0) {
            connected_node = rand() % node_count;
        }

        // Connect the unconnected node to a randomly chosen connected node
        (*adj_matrix)[connected_node][unconnected_node] = 1;

        // Mark the unconnected node as connected
        connected[unconnected_node] = 1;
        connected_count++;

        printf("Connected node %d to node %d\n", unconnected_node, connected_node);
    }
}

// Function to print the adjacency table
void print_adj_table(int adj_table[MAX_NODES][MAX_NODES]) {
    printf("Adjacency Matrix:\n");
    for (int i = 0; i < node_count; i++) {
        for (int j = 0; j < node_count; j++) {
            printf("%d ", adj_table[i][j]);
        }
        printf("\n");
    }
}

// Example of graph traversal to test the connectivity
void execute_graph(int start_node, int max_depth, int current_depth, int adj_matrix[MAX_NODES][MAX_NODES]) {
    printf("Reordering Local Edges for Depth: %d\n", current_depth);
    reorder_edges(&adj_table);
    int *queue = malloc(sizeof(int) * node_count);
    if (!queue) {
        perror("Queue allocation failed");
        exit(EXIT_FAILURE);
    }

    int front = 0, rear = 0;
    int depth = 0;
    bool visited[node_count];
    for (int i = 0; i < node_count; i++) visited[i] = false;

    // Enqueue the starting node
    queue[rear++] = start_node;
    visited[start_node] = true;

    while (front < rear) {
        int level_size = rear - front;
        for (int i = 0; i < level_size; i++) {
            int current = queue[front++];

            if (rand() % 2 == 0 && current_depth < max_depth) { // 50% chance to recurse deeper
                printf("Recursively calling execute_graph from node %d at depth %d\n", start_node, current_depth);
                execute_graph(current, max_depth, current_depth + 1, adj_matrix);
            }
            
            // if (current_depth == 0)
            printf("Executing node: %d at Depth %d\n", current, current_depth);
            // Execute current node
            nodes[current]();

            // Add neighbors to the queue
            for (int neighbor = 0; neighbor < node_count; neighbor++) {
                if (adj_matrix[current][neighbor] && !visited[neighbor]) {
                    queue[rear++] = neighbor;
                    visited[neighbor] = true;
                }
            }
        }
    }

    free(queue);  // Free allocated memory
}