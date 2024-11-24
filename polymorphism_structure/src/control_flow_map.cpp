// src/control_flow_map.cpp
#include "../include/control_flow_node.h"
#include <map>
#include <ctime>
#include <iostream>
#include <cstdlib>

namespace control_flow_obfuscation {

    // Example mapping (correctly defined as a map)
    std::map<FuncPtr, ControlFlowNode> control_flow_map;

    // Example functions (terminate definitively)
    void fun1() {
        std::cout << "Executing fun1" << std::endl;
    }

    void fun2() {
        std::cout << "Executing fun2" << std::endl;
    }

    void fun3() {
        std::cout << "Executing fun3" << std::endl;
    }

    // Add nodes and transitions
    // I can already see this causing infinite loops. I need to make a ruleset to make sure they definitively terminate
    // This is also not quite what i had in mind. It's something, but i would rather substitute already existing instruction with the map with equivalent ones using inline assembly to obfuscate control flow. This is still a great step to randomize control flow, although i don't know how I should approach randomizing the order (the intended function not always first) the functions are processed... maybe jump to the functions and keep the first call intact to someday break out of the infinite random call loop to call the actual function. Then I would still have the same issues as before, because it's always the last function before returning to normalized program execution
    // In conclusion: Instruction substitution on existing functions using inline assembly should solve all my problems. 
    void init_control_flow_map() {
        control_flow_map.insert({&fun1, ControlFlowNode(1, false, {&fun2, &fun3})});
        control_flow_map.insert({&fun2, ControlFlowNode(2, true, {&fun3})});
        control_flow_map.insert({&fun3, ControlFlowNode(3, false, {})});
    }

    // Get a random next function pointer from the control flow map
    FuncPtr get_control_flow(FuncPtr func) {
        if (control_flow_map.find(func) != control_flow_map.end()) {
            ControlFlowNode node = control_flow_map[func];

            // If there are no next nodes, return null
            if (node.nextNodes.empty()) {
                return nullptr;
            }

            // Seed the random number generator with the current time
            std::srand(static_cast<unsigned>(std::time(0)));

            // Select a random function pointer from nextNodes
            int randomIndex = std::rand() % node.nextNodes.size();
            return node.nextNodes[randomIndex];
        }

        // Return null if the function is not found in the map
        return nullptr;
    }

} // namespace control_flow_obfuscation
