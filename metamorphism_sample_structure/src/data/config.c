#include "config.h"

__attribute__((section(".meta"))) uint8_t metadata_section[4096] = {0};

unsigned int prng_seed = PRNG_SEED;

// unsigned int state_variable to make sure the correct functionality inside the nodes is executed. after each execution it might get xored with a specific other variable to make sure they go in order to resolve the issue of the control flow spidering executing all nodes at once