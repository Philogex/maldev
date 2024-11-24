// include/control_flow_node.h
#ifndef CONTROL_FLOW_NODE_H
#define CONTROL_FLOW_NODE_H

#include <map>
#include <vector>
#include <functional>

namespace control_flow_obfuscation {

    using FuncPtr = void(*)();

    struct ControlFlowNode {
        int id;
        bool isGarbage;
        std::vector<FuncPtr> nextNodes;

        // Default constructor
    	ControlFlowNode()
        	: id(0), isGarbage(false), nextNodes({}) {}

        // Constructor
        ControlFlowNode(int id, bool isGarbage, std::vector<FuncPtr> nextNodes)
            : id(id), isGarbage(isGarbage), nextNodes(nextNodes) {}
    };

    extern std::map<FuncPtr, ControlFlowNode> control_flow_map;
    extern void init_control_flow_map();
    extern FuncPtr get_control_flow(FuncPtr func);
    extern void fun1();
    extern void fun2();
    extern void fun3();

} // namespace control_flow_obfuscation

#endif // CONTROL_FLOW_NODE_H