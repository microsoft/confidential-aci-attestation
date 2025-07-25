#include "files.h"
#include <stdio.h>
#include <stdlib.h>


char* read_file(const char* path) {

    // Get file descriptor
    FILE* f = fopen(path, "rb");
    if (!f) return NULL;

    // Get file size
    if (fseek(f, 0, SEEK_END) != 0) { fclose(f); return NULL; }
    long size = ftell(f);
    if (size < 0) { fclose(f); return NULL; }

    // Move back to the beginning of the file
    if (fseek(f, 0, SEEK_SET) != 0) { fclose(f); return NULL; }

    // Allocate memory for the file contents
    char* buffer = malloc(size + 1);
    if (!buffer) { fclose(f); return NULL; }

    // Read the file contents into the buffer
    size_t read_size = fread(buffer, 1, size, f);
    fclose(f);
    if (read_size != (size_t)size) { free(buffer); return NULL; }

    // Null-terminate the buffer
    buffer[size] = '\0';
    return buffer;
}