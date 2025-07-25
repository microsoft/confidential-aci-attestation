// test_json_unit.c - Unit tests for get_json_field

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "lib/json.h"

static int test_simple(void) {
    const char *json = "{\"foo\":\"bar\"}";
    char *val = get_json_field(json, "foo");
    if (!val) {
        fprintf(stderr, "[simple] Expected non-NULL\n");
        return 1;
    }
    if (strcmp(val, "bar") != 0) {
        fprintf(stderr, "[simple] FAILED: expected 'bar', got '%s'\n", val);
        free(val);
        return 1;
    }
    free(val);
    printf("[PASS] simple extraction\n");
    return 0;
}

static int test_spaces(void) {
    const char *json = "{\"foo\" :   \"baz\"}";
    char *val = get_json_field(json, "foo");
    if (!val) {
        fprintf(stderr, "[spaces] Expected non-NULL\n");
        return 1;
    }
    if (strcmp(val, "baz") != 0) {
        fprintf(stderr, "[spaces] FAILED: expected 'baz', got '%s'\n", val);
        free(val);
        return 1;
    }
    free(val);
    printf("[PASS] spaces handling\n");
    return 0;
}

static int test_missing(void) {
    char *val = get_json_field("{}", "foo");
    if (val) {
        fprintf(stderr, "[missing] Expected NULL\n");
        free(val);
        return 1;
    }
    printf("[PASS] missing key returns NULL\n");
    return 0;
}

// Test numeric values
// Test malformed JSON input returns NULL
static int test_malformed(void) {
    char *val = get_json_field("{bad json", "foo");
    if (val) {
        fprintf(stderr, "[malformed] Expected NULL\n");
        free(val);
        return 1;
    }
    printf("[PASS] malformed JSON returns NULL\n");
    return 0;
}

// Test unescape_json behavior for escape sequences
static int test_unescape(void) {
    const char *s = "Line1\\nLine2\\r\\\\End";
    char *out = unescape_json(s);
    if (!out) {
        fprintf(stderr, "[unescape] NULL output\n");
        return 1;
    }
    if (strcmp(out, "Line1\nLine2\r\\End") != 0) {
        fprintf(stderr, "[unescape] FAILED: got '%s'\n", out);
        free(out);
        return 1;
    }
    free(out);
    printf("[PASS] unescape_json conversion\n");
    return 0;
}

// Test unescape_json NULL input returns NULL
static int test_unescape_null(void) {
    char *out = unescape_json(NULL);
    if (out) {
        fprintf(stderr, "[unescape_null] Expected NULL\n");
        free(out);
        return 1;
    }
    printf("[PASS] unescape_json(NULL) returns NULL\n");
    return 0;
}

int main(void) {
    // Declare test suite
    printf("=== test_json_unit ===\n");
    if (test_simple()) return 1;
    if (test_spaces()) return 1;
    if (test_missing()) return 1;
    if (test_malformed()) return 1;
    if (test_unescape()) return 1;
    if (test_unescape_null()) return 1;
    printf("All tests passed\n");
    return 0;
}
