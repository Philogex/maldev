/*
var public_signing_key
var otp_key
*/

#ifndef CONFIG_H
#define CONFIG_H

#include <stdint.h>

#define PRNG_SEED (0000000000 + __COUNTER__)
#define SHARED_MEMORY_NAME "Meta\\ProcessInfo"
extern unsigned int prng_seed;
//this is necessary since i might strip the executable later on. also this needs to be dynamically calculated...
extern __attribute__((section(".meta"))) uint8_t metadata_section[4096];

#endif // CONFIG_H