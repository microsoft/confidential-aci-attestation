// test_hex_unit.c - Unit tests for hex_encode and hex_decode

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include "lib/hex.h"

static int test_encode(void) {
    struct {
        const uint8_t *data;
        size_t len;
        const char *expected;
    } cases[] = {
        { (const uint8_t *)"", 0, "" },
        { (const uint8_t *)"\x00\xFF\x10\x20", 4, "00 ff 10 20" },
    };
    size_t n = sizeof(cases) / sizeof(cases[0]);
    for (size_t i = 0; i < n; i++) {
        size_t out_len = 0;
        char *out = hex_encode(cases[i].data, cases[i].len, 16, &out_len);
        if (!out) {
            fprintf(stderr, "[encode %zu] Allocation failure\n", i);
            return 1;
        }
        if (strcmp(out, cases[i].expected) != 0) {
            fprintf(stderr, "[encode %zu] FAILED: expected '%s', got '%s'\n", i, cases[i].expected, out);
            free(out);
            return 1;
        }
        if (strlen(cases[i].expected) != out_len) {
            fprintf(stderr, "[encode %zu] FAILED: expected length %zu, got %zu\n", i, strlen(cases[i].expected), out_len);
            free(out);
            return 1;
        }
        free(out);
        printf("[PASS] encode case %zu\n", i);
    }
    return 0;
}

static int test_decode(void) {
    struct {
        const char *hex;
        size_t hex_len;
        uint8_t expected[4];
        size_t expected_len;
    } cases[] = {
        { "00 ff 10 20", 11, {0x00,0xFF,0x10,0x20}, 4 },
        { "00FF1020", 8, {0x00,0xFF,0x10,0x20}, 4 },
        { "AA bb", 5, {0xAA,0xBB}, 2 },
    };
    size_t n = sizeof(cases) / sizeof(cases[0]);
    for (size_t i = 0; i < n; i++) {
        size_t out_len = 0;
        uint8_t *out = hex_decode(cases[i].hex, cases[i].hex_len, &out_len);
        if (!out) {
            fprintf(stderr, "[decode %zu] Allocation failure or invalid input\n", i);
            return 1;
        }
        if (out_len != cases[i].expected_len) {
            fprintf(stderr, "[decode %zu] FAILED: expected length %zu, got %zu\n", i, cases[i].expected_len, out_len);
            free(out);
            return 1;
        }
        if (memcmp(out, cases[i].expected, out_len) != 0) {
            fprintf(stderr, "[decode %zu] FAILED: output mismatch\n", i);
            free(out);
            return 1;
        }
        free(out);
        printf("[PASS] decode case %zu\n", i);
    }
    return 0;
}

static int test_errors(void) {
    size_t out_len;
    uint8_t *out;

    out = hex_decode("0", 1, &out_len);
    if (out) { fprintf(stderr, "[error odd] Expected NULL\n"); free(out); return 1; }
    printf("[PASS] odd length error\n");

    out = hex_decode("zz", 2, &out_len);
    if (out) { fprintf(stderr, "[error invalid] Expected NULL\n"); free(out); return 1; }
    printf("[PASS] invalid char error\n");

    return 0;
}

int main(void) {
    // Declare test suite
    printf("=== test_hex_unit ===\n");
    if (test_encode()) return 1;
    if (test_decode()) return 1;
    if (test_errors()) return 1;
    printf("All tests passed\n");
    return 0;
}