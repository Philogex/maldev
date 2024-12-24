/*
func do_random_stuff_1
func do_random_stuff_2
func do_random_stuff_3
func do_random_stuff 4
func do_random_stuff 5

func main
	decrypt_control_flow
	beacon

	loop parse_incoming_command
	loop keep_alive

	encrypt_control_flow
	overwrite_disk_binary
*/

#include <stdio.h>
#include <stdlib.h>
#include "control_flow_handler.h"
#include "../data/adjacency_table.h"

int main() {
    // Step 1: Print a banner (optional, for visual clarity)
    printf("=== Graph Execution Proof of Concept ===\n");

    // Step 3: Execute the graph starting from Node 0, with a depth limit of 3
    printf("Executing graph from Node 0 with max depth of 3:\n");
    execute_graph(0, 2, 0, adj_table);

    // Step 4: Clean exit
    printf("=== Execution Complete ===\n");
    return 0;
}
