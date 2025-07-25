#include "hex.h"
#include <stdlib.h>
#include <ctype.h>

char* hex_encode(const uint8_t* data, size_t input_length, size_t bytes_per_line, size_t* output_length) {
    if (!data) return NULL;

    // Determine output length pointer (use local variable if caller did not provide one)
    size_t local_len = 0;
    size_t* out_len = output_length ? output_length : &local_len;
    *out_len = 0;
    *out_len += input_length * 2;                           // 2 hex chars per byte
    *out_len += (input_length > 0 ? input_length - 1 : 0);  // 1 space or newline per byte

    // Allocate the output string (+1 for NUL terminator)
    char* output = malloc(*out_len + 1);
    if (!output) return NULL;

    // Format the hex data
    static const char hex_digits[] = "0123456789abcdef";
    for (size_t i = 0; i < input_length; i++) {
        uint8_t byte = data[i];
        size_t pos = i * 3;
        output[pos]     = hex_digits[(byte >> 4) & 0xF];
        output[pos + 1] = hex_digits[byte & 0xF];
        if (i + 1 < input_length) {
            if ((i + 1) % bytes_per_line == 0) output[pos + 2] = '\n';
            else output[pos + 2] = ' ';
        }
    }

    output[*out_len] = '\0';

    return output;
}

uint8_t* hex_decode(const char* hex, size_t input_length, size_t* output_length) {
    if (!hex) return NULL;

    // Count hex digits, skip whitespace
    size_t digit_count = 0;
    for (size_t i = 0; i < input_length; i++) {
        if (isxdigit((unsigned char)hex[i])) {
            digit_count++;
        } else if (isspace((unsigned char)hex[i])) {
            continue;
        } else {
            return NULL;
        }
    }
    if (digit_count % 2 != 0) return NULL;

    // Determine output length pointer (use local variable if caller did not provide one)
    size_t local_len = 0;
    size_t* out_len = output_length ? output_length : &local_len;
    *out_len = digit_count / 2;
    if (*out_len == 0) {
        return malloc(1);
    }

    // Allocate space for the output
    uint8_t* output = malloc(*out_len);
    if (!output) return NULL;

    size_t hex_idx = 0;
    size_t output_idx = 0;
    while (output_idx < *out_len) {

        // Read high nibble
        int vhi = -1;
        while (hex_idx < input_length) {
            char c = hex[hex_idx++];
            if (isxdigit((unsigned char)c)) {
                vhi = (isdigit((unsigned char)c) ? c - '0' : (isupper((unsigned char)c) ? c - 'A' + 10 : c - 'a' + 10));
                break;
            }
        }
        if (vhi < 0) { free(output); return NULL; }

        // Read low nibble
        int vlo = -1;
        while (hex_idx < input_length) {
            char c = hex[hex_idx++];
            if (isxdigit((unsigned char)c)) {
                vlo = (isdigit((unsigned char)c) ? c - '0' : (isupper((unsigned char)c) ? c - 'A' + 10 : c - 'a' + 10));
                break;
            }
        }
        if (vlo < 0) { free(output); return NULL; }

        // Combine high and low nibbles into a byte
        output[output_idx++] = (uint8_t)((vhi << 4) | vlo);
    }

    return output;
}