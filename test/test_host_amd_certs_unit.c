// test_host_amd_certs_unit.c - Unit tests for get_host_amd_certs

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include "lib/base64.h"
#include "lib/host_amd_certs.h"
#include "lib/json.h"

static int test_get_certs(void) {
    // Retrieve base64-encoded JSON blob
    char *b64 = get_host_amd_certs();
    if (!b64) {
        fprintf(stderr, "[get_certs] Expected non-NULL base64\n");
        return 1;
    }
    size_t raw_len = 0;
    uint8_t *raw = base64_decode(b64, strlen(b64), &raw_len);
    free(b64);
    if (!raw) {
        fprintf(stderr, "[base64_decode] FAILED\n");
        return 1;
    }
    // Null-terminate JSON string
    char *json = malloc(raw_len + 1);
    if (!json) {
        free(raw);
        fprintf(stderr, "[malloc] FAILED\n");
        return 1;
    }
    memcpy(json, raw, raw_len);
    json[raw_len] = '\0';
    free(raw);
    // Extract field
    char *val = get_json_field(json, "cacheControl");
    if (!val) {
        fprintf(stderr, "[cacheControl] Expected non-NULL\n");
        free(json);
        return 1;
    }
    if (strcmp(val, "86400") != 0) {
        fprintf(stderr, "[cacheControl] FAILED: expected '86400', got '%s'\n", val);
        free(val);
        free(json);
        return 1;
    }
    free(val);
    free(json);
    printf("[PASS] cacheControl=86400\n");
    return 0;
}

int main(void) {
    printf("=== test_host_amd_certs_unit ===\n");
    if (test_get_certs()) return 1;
    printf("All tests passed\n");
    return 0;
}