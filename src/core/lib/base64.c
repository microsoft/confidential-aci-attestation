#include "base64.h"
#include <openssl/evp.h>
#include <stdlib.h>


char* base64_encode(
    const uint8_t* data,
    size_t input_length,
    size_t* output_length
) {
    if (!data) return NULL;

    // Calculate the output length
    size_t local_len = 0;
    size_t* out_len = output_length ? output_length : &local_len;
    *out_len = 4 * ((input_length + 2) / 3);

    // Allocate space for the Base64-encoded string
    unsigned char* output = malloc(*out_len + 1);
    if (!output) return NULL;

    // EVP_EncodeBlock writes exactly 4 * ((in_len+2)/3) bytes (no '\0')
    int written = EVP_EncodeBlock(output, data, (int)input_length);
    if (written < 0) {
        free(output);
        return NULL;
    }

    // Null-terminate
    output[written] = '\0';

    return (char*)output;
}


uint8_t* base64_decode(
    const char* data,
    size_t input_length,
    size_t* output_length
) {
    if (!data) return NULL;

    // Use local length if caller does not request output length
    size_t local_len = 0;
    size_t* out_len = output_length ? output_length : &local_len;

    // Handle empty input: return an allocatable empty buffer
    if (input_length == 0) {
        *out_len = 0;
        return malloc(1);
    }

    // Count padding characters '=' at the end
    size_t padding = 0;
    for (size_t i = input_length; i > 0 && data[i - 1] == '='; i--) {
        padding++;
    }

    // Calculate output length: 3 bytes per 4 Base64 chars
    *out_len = (input_length / 4) * 3;

    // Allocate space for the output (ensure at least 1 byte)
    size_t alloc_size = *out_len > 0 ? *out_len : 1;
    unsigned char* output = malloc(alloc_size);
    if (!output) return NULL;

    // EVP_DecodeBlock decodes input_length bytes and returns length (including padding)
    int decoded_len = EVP_DecodeBlock(output, (const unsigned char*)data, (int)input_length);
    if ((size_t)decoded_len != *out_len) {
        free(output);
        return NULL;
    }

    // Adjust length based on padding
    if (padding > 0) {
        *out_len -= padding;
    }

    return output;
}
