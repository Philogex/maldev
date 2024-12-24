#ifndef CONTROL_FLOW_HANDLER_H
#define CONTROL_FLOW_HANDLER_H

#include "../data/adjacency_table.h"
#include "../data/config.h"

void execute_graph(int start_node, int max_depth, int current_depth, int adj_matrix[MAX_NODES][MAX_NODES]);
void reorder_edges(int (*adj_matrix)[MAX_NODES][MAX_NODES]);

#endif // CONTROL_FLOW_HANDLER_H