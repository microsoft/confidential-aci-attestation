#ifndef SHA256_H
#define SHA256_H

#include <stdint.h>
#include <stddef.h>


// Computes SHA-256 hash of input data.
// - data: pointer to input bytes.
// - length: length of input data.
// Returns:
//   Malloc'd buffer containing 32-byte digest, or NULL on failure. Caller must free().
uint8_t* sha256(const uint8_t* data, size_t length);


// Computes SHA-256 hash of input data.
// - data: pointer to input bytes.
// - length: length of input data.
// Returns:
//   Malloc'd buffer containing 32-byte digest, or NULL on failure. Caller must free().
uint8_t* sha384(const uint8_t* data, size_t length);

#endif // SHA256_H