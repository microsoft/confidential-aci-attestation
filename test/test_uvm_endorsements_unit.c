// test_uvm_endorsements_unit.c - Unit tests for get_uvm_endorsements

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include "lib/uvm_endorsements.h"
#include "lib/base64.h"

static int test_uvm_endorsements_nonnull(void) {
    char* b64 = get_uvm_endorsements();
    if (!b64) {
        fprintf(stderr, "[get_uvm_endorsements] returned NULL\n");
        return 1;
    }
    free(b64);
    printf("[PASS] get_uvm_endorsements returned non-null\n");
    return 0;
}

static int test_uvm_endorsements_decode(void) {
    char* b64 = get_uvm_endorsements();
    size_t len = 0;
    uint8_t* buf = base64_decode(b64, strlen(b64), &len);
    free(b64);
    if (!buf || len == 0) {
        fprintf(stderr, "[decode] FAILED to decode or empty output\n");
        free(buf);
        return 1;
    }
    free(buf);
    printf("[PASS] uvm_endorsements base64 decode\n");
    return 0;
}

int main(void) {
    printf("=== test_uvm_endorsements_unit ===\n");
    if (test_uvm_endorsements_nonnull()) return 1;
    if (test_uvm_endorsements_decode()) return 1;
    printf("All tests passed\n");
    return 0;
}