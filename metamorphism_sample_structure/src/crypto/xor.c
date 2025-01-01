#include <stdio.h>
#include <string.h>
#include "xor.h"

void xor(unsigned char *data, size_t dataSize, unsigned char key) {
    for (size_t i = 0; i < dataSize; i++) {
        data[i] ^= key;  // XOR each byte with the key
    }
}