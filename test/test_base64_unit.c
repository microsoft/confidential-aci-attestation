// test_base64_unit.c - Unit tests for base64_encode
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include "lib/base64.h"

struct test_vector {
    const char* input;
    const char* expected;
};

// test_base64_unit.c - Unit tests and integration checks for base64_encode
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include "lib/base64.h"

// Test known Base64 vectors (RFC 4648)
static int test_literals(void) {
    struct {
        const char* name;
        const char* input;
        const char* expected;
    } cases[] = {
        {"empty", "", ""},
        {"one byte", "f", "Zg=="},
        {"two bytes", "fo", "Zm8="},
        {"three bytes", "foo", "Zm9v"},
        {"four bytes", "foob", "Zm9vYg=="},
        {"five bytes", "fooba", "Zm9vYmE="},
        {"six bytes", "foobar", "Zm9vYmFy"},
    };
    size_t n = sizeof(cases) / sizeof(cases[0]);
    for (size_t i = 0; i < n; i++) {
        size_t out_len = 0;
        char* out = base64_encode((const uint8_t*)cases[i].input,
                                  strlen(cases[i].input),
                                  &out_len);
        if (!out) {
            fprintf(stderr, "[%s] Allocation failure\n", cases[i].name);
            return 1;
        }
        if (strcmp(out, cases[i].expected) != 0) {
            fprintf(stderr,
                    "[%s] FAILED: expected '%s', got '%s'\n",
                    cases[i].name, cases[i].expected, out);
            free(out);
            return 1;
        }
        free(out);
        printf("[PASS] %s\n", cases[i].name);
    }
    return 0;
}

// Test binary input handling
static int test_binary(void) {
    const char* name = "binary (00 FF 10 20)";
    uint8_t data[] = {0x00, 0xFF, 0x10, 0x20};
    const char* expected = "AP8QIA==";
    size_t out_len = 0;
    char* out = base64_encode(data, sizeof(data), &out_len);
    if (!out) {
        fprintf(stderr, "[%s] Allocation failure\n", name);
        return 1;
    }
    if (strcmp(out, expected) != 0) {
        fprintf(stderr,
                "[%s] FAILED: expected '%s', got '%s'\n",
                name, expected, out);
        free(out);
        return 1;
    }
    free(out);
    printf("[PASS] %s\n", name);
    return 0;
}

// Integration test: compare text inputs against /usr/bin/base64
static int test_integration(void) {
    struct {
        const char* name;
        const char* input;
    } cases[] = {
        {"empty", ""},
        {"one byte", "f"},
        {"two bytes", "fo"},
        {"three bytes", "foo"},
        {"four bytes", "foob"},
        {"five bytes", "fooba"},
        {"six bytes", "foobar"},
    };
    size_t n = sizeof(cases) / sizeof(cases[0]);
    for (size_t i = 0; i < n; i++) {
        const char* name = cases[i].name;
        const char* input = cases[i].input;
        char cmd[256];
        int ret = snprintf(cmd, sizeof(cmd),
                           "printf '%%s' \"%s\" | base64 | tr -d '\\n'",
                           input);
        if (ret < 0 || (size_t)ret >= sizeof(cmd)) {
            fprintf(stderr, "[%s] Command too long\n", name);
            return 1;
        }
        FILE* fp = popen(cmd, "r");
        if (!fp) {
            perror("popen");
            return 1;
        }
        char sys_out[512] = {0};
        if (!fgets(sys_out, sizeof(sys_out), fp)) {
            // Empty input produces no output
            pclose(fp);
            if (strlen(input) == 0) {
                printf("[PASS] %s (integration)\n", name);
                continue;
            }
            fprintf(stderr, "[%s] Failed to read system base64 output\n", name);
            return 1;
        }
        pclose(fp);
        size_t sys_len = strlen(sys_out);
        size_t our_len = 0;
        char* our_out = base64_encode((const uint8_t*)input,
                                      strlen(input),
                                      &our_len);
        if (!our_out) {
            fprintf(stderr, "[%s] Allocation failure\n", name);
            return 1;
        }
        if (sys_len != our_len || memcmp(sys_out, our_out, sys_len) != 0) {
            sys_out[sys_len] = '\0';
            fprintf(stderr,
                    "[%s] INTEGRATION FAILED: expected '%s', got '%s'\n",
                    name, sys_out, our_out);
            free(our_out);
            return 1;
        }
        free(our_out);
        printf("[PASS] %s (integration)\n", name);
    }
    return 0;
}

int main(void) {
    // Declare test suite
    printf("=== test_base64_unit ===\n");
    if (test_literals())    return 1;
    if (test_binary())      return 1;
    if (test_integration()) return 1;
    printf("All tests passed\n");
    return 0;
}