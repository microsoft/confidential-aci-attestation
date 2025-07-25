#include <stdint.h>
#include <stddef.h>

#ifndef BASE64_H
#define BASE64_H


// Encodes the input data to a null-terminated Base64 string (standard alphabet).
// Parameters:
// - data: pointer to input bytes.
// - input_length: length of input in bytes.
// - output_length: pointer to size_t to store length of encoded output
//                  (excluding null terminator).
// Returns:
//   Allocated null-terminated encoded string, or NULL on failure. Caller must
//   free() the returned string.
char* base64_encode(const uint8_t* data, size_t input_length, size_t* output_length);


// Decodes Base64-encoded data (no line breaks) into binary.
// Parameters:
// - data: pointer to Base64-encoded string; input_length: length of the encoded
//         data.
// - output_length: pointer to size_t to receive decoded byte length.
// Returns:
//   Malloc'd buffer with decoded bytes, or NULL on failure. Caller must free().
uint8_t* base64_decode(const char* data, size_t input_length, size_t* output_length);


#endif // BASE64_H