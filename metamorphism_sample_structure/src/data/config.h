/*
var public_signing_key
var otp_key
*/

#ifndef CONFIG_H
#define CONFIG_H

#define PRNG_SEED (0000000000 + __COUNTER__)
extern unsigned int prng_seed;

#endif // CONFIG_H