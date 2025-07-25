#include "json.h"
#include <stdlib.h>
#include <string.h>

char* get_json_field(const char* json, const char* key)
{
    size_t key_len = strlen(key);

    // Build search pattern "key"
    char* pattern = malloc(key_len + 3);
    if (!pattern)
        return NULL;
    pattern[0] = '\"';
    for (size_t i = 0; i < key_len; i++)
        pattern[i + 1] = key[i];
    pattern[key_len + 1] = '\"';
    pattern[key_len + 2] = '\0';

    // Search for the key in the JSON string
    char* pos = strstr(json, pattern);
    free(pattern);
    if (!pos)
        pos = strstr(json, key);
    if (!pos)
        return NULL;

    // Find the colon after the key
    char* colon = strchr(pos, ':');
    if (!colon)
        return NULL;
    char* start = colon + 1;
    while (*start == ' ' || *start == '\"')
        start++;
    char* end = strchr(start, '\"');
    if (!end)
        return NULL;

    // Extract the value
    size_t len = end - start;
    char* result = malloc(len + 1);
    if (!result)
        return NULL;
    for (size_t i = 0; i < len; i++)
        result[i] = start[i];
    result[len] = '\0';
    return result;
}

char* unescape_json(const char* s) {
    if (!s) return NULL;

    // Allocate memory for the output string
    size_t len = strlen(s);
    char* output = malloc(len + 1);
    if (!output) return NULL;

    // Covert escape chars
    char* output_ptr = output;
    for (size_t i = 0; i < len; i++) {
        if (s[i] == '\\' && i + 1 < len) {
            char next = s[i+1];
            if (next == 'n') {
                *output_ptr++ = '\n';
                i++;
            } else if (next == 'r') {
                *output_ptr++ = '\r';
                i++;
            } else if (next == '\\') {
                *output_ptr++ = '\\';
                i++;
            } else {
                *output_ptr++ = s[i];
            }
        } else {
            *output_ptr++ = s[i];
        }
    }

    *output_ptr = '\0';

    return output;
}