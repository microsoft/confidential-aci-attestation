// test_files_unit.c - Unit tests for read_file

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "lib/files.h"

static int test_read_file(void) {
    char fname[L_tmpnam];
    if (!tmpnam(fname)) {
        fprintf(stderr, "tmpnam failed\n");
        return 1;
    }
    FILE *f = fopen(fname, "wb");
    if (!f) {
        perror("fopen");
        return 1;
    }
    const char *text = "hello world";
    size_t len = strlen(text);
    if (fwrite(text, 1, len, f) != len) {
        perror("fwrite");
        fclose(f);
        remove(fname);
        return 1;
    }
    fclose(f);

    char *buf = read_file(fname);
    if (!buf) {
        fprintf(stderr, "read_file returned NULL\n");
        remove(fname);
        return 1;
    }
    if (strcmp(buf, text) != 0) {
        fprintf(stderr, "Expected '%s', got '%s'\n", text, buf);
        free(buf);
        remove(fname);
        return 1;
    }
    free(buf);
    if (remove(fname) != 0) {
        perror("remove");
        return 1;
    }
    printf("[PASS] read existing file\n");
    return 0;
}

static int test_read_nonexistent(void) {
    const char *fname = "nonexistent_file_12345.txt";
    char *buf = read_file(fname);
    if (buf) {
        fprintf(stderr, "Expected NULL for nonexistent file\n");
        free(buf);
        return 1;
    }
    printf("[PASS] read nonexistent file\n");
    return 0;
}

int main(void) {
    // Declare test suite
    printf("=== test_files_unit ===\n");
    if (test_read_file()) return 1;
    if (test_read_nonexistent()) return 1;
    printf("All tests passed\n");
    return 0;
}