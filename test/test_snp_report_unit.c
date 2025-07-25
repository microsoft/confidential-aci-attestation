// test_snp_report_unit.c - Unit tests for snp_report

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include "lib/snp_report.h"

// Test the format_report_data helper
static int test_format(void) {
    const uint8_t data[] = {'A', 'B', 'C'};
    char *out = format_report_data(data, 3);
    if (!out) {
        fprintf(stderr, "[format] NULL output\n");
        return 1;
    }
    const char *expected = "41 42 43\n(ABC)";
    if (strcmp(out, expected) != 0) {
        fprintf(stderr, "[format] FAILED: expected '%s', got '%s'\n", expected, out);
        free(out);
        return 1;
    }
    free(out);
    printf("[PASS] format_report_data\n");
    return 0;
}

// Test get_snp_report error on NULL output pointer
// Test null out_report pointer returns error
static int test_get_report_null(void) {
    uint8_t report_data[64] = {0};
    int rc = get_snp_report(report_data, NULL);
    if (rc != -1) {
        fprintf(stderr, "[get_null] FAILED: expected -1, got %d\n", rc);
        return 1;
    }
    printf("[PASS] get_snp_report NULL output error\n");
    return 0;
}

// Test get_snp_report virtual fallback
// Test virtual fallback path (no /dev/sev support)
static int test_get_report_virtual(void) {
    uint8_t report_data[64] = {0};
    SnpReport rep;
    int rc = get_snp_report(report_data, &rep);
    if (rc != 0) {
        fprintf(stderr, "[get_report] FAILED: expected 0, got %d\n", rc);
        return 1;
    }
    printf("[PASS] virtual SNP report generation (rc=%d)\n", rc);
    return 0;
}

// Test format_report_data for binary-only data (no ASCII)
static int test_format_binary_only(void) {
    uint8_t bin[] = {0xff, 0x00, 0x10};
    char *out = format_report_data(bin, sizeof(bin));
    if (!out) {
        fprintf(stderr, "[format binary] NULL output\n");
        return 1;
    }
    if (strcmp(out, "ff 00 10") != 0) {
        fprintf(stderr, "[format binary] FAILED: got '%s'\n", out);
        free(out);
        return 1;
    }
    free(out);
    printf("[PASS] format_report_data binary-only path\n");
    return 0;
}

int main(void) {
    printf("=== test_snp_report_unit ===\n");
    if (test_format()) return 1;
    if (test_get_report_null()) return 1;
    if (test_get_report_virtual()) return 1;
    if (test_format_binary_only()) return 1;
    printf("All tests passed\n");
    return 0;
}