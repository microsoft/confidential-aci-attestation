// test_sha256_unit.c - Unit tests for sha256

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include "lib/sha256.h"

// Helper: convert binary data to lowercase hex string (no spaces)
static void bin2hex(const uint8_t *bin, size_t len, char *hex) {
    static const char hex_digits[] = "0123456789abcdef";
    for (size_t i = 0; i < len; i++) {
        hex[2*i]     = hex_digits[bin[i] >> 4];
        hex[2*i + 1] = hex_digits[bin[i] & 0xF];
    }
    hex[2*len] = '\0';
}

static int test_sha256_empty(void) {
    const uint8_t data[] = "";
    uint8_t *digest = sha256(data, 0);
    if (!digest) {
        fprintf(stderr, "[empty] sha256 returned NULL\n");
        return 1;
    }
    char hexstr[65];
    bin2hex(digest, 32, hexstr);
    free(digest);
    const char *expected = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
    if (strcmp(hexstr, expected) != 0) {
        fprintf(stderr, "[empty] FAILED: expected '%s', got '%s'\n", expected, hexstr);
        return 1;
    }
    printf("[PASS] sha256 empty string\n");
    return 0;
}

static int test_sha256_abc(void) {
    const uint8_t data[] = "abc";
    uint8_t *digest = sha256(data, 3);
    if (!digest) {
        fprintf(stderr, "[abc] sha256 returned NULL\n");
        return 1;
    }
    char hexstr[65];
    bin2hex(digest, 32, hexstr);
    free(digest);
    const char *expected = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
    if (strcmp(hexstr, expected) != 0) {
        fprintf(stderr, "[abc] FAILED: expected '%s', got '%s'\n", expected, hexstr);
        return 1;
    }
    printf("[PASS] sha256 \"abc\"\n");
    return 0;
}

static int test_sha256_null(void) {
    uint8_t *digest = sha256(NULL, 0);
    if (digest) {
        fprintf(stderr, "[null] Expected NULL digest\n");
        free(digest);
        return 1;
    }
    printf("[PASS] sha256 NULL data\n");
    return 0;
}

// Test SHA-256 on a well-known sentence
static int test_sha256_quick(void) {
    const uint8_t data[] = "The quick brown fox jumps over the lazy dog";
    uint8_t *digest = sha256(data, strlen((const char*)data));
    if (!digest) {
        fprintf(stderr, "[quick] sha256 returned NULL\n");
        return 1;
    }
    char hexstr[65];
    bin2hex(digest, 32, hexstr);
    free(digest);
    const char *expected = "d7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592";
    if (strcmp(hexstr, expected) != 0) {
        fprintf(stderr, "[quick] FAILED: expected '%s', got '%s'\n", expected, hexstr);
        return 1;
    }
    printf("[PASS] sha256 quick sentence\n");
    return 0;
}

int main(void) {
    // Declare test suite
    printf("=== test_sha256_unit ===\n");
    if (test_sha256_empty()) return 1;
    if (test_sha256_abc()) return 1;
    if (test_sha256_null()) return 1;
    if (test_sha256_quick()) return 1;
    printf("All tests passed\n");
    return 0;
}
