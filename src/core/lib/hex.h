#ifndef HEX_H
#define HEX_H

#include <stddef.h>
#include <stdint.h>

// Encodes binary data to a null-terminated lowercase hexadecimal string,
// with each byte separated by a space (e.g., "0a ff 01").
// Parameters:
// - data: pointer to input bytes.
// - input_length: length of input in bytes.
// - bytes_per_line: number of bytes to print before adding a newline.
// - output_length: pointer to size_t to store length of encoded output (excluding null terminator).
// Returns:
//   Malloc'd null-terminated hex string, or NULL on failure. Caller must free().
char* hex_encode(const uint8_t* data, size_t input_lengt, size_t bytes_per_line, size_t* output_length);

// Decodes a hexadecimal string (with optional spaces) into binary data.
// - hex: pointer to hex string; input_length: length of the hex string.
// - input_length: length of input in bytes.
// - output_length: pointer to size_t to receive decoded byte length.
// Returns:
//   Malloc'd buffer with decoded bytes, or NULL on failure. Caller must free().
uint8_t* hex_decode(const char* hex, size_t input_length, size_t* output_length);

#endif // HEX_H