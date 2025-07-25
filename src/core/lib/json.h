#ifndef JSON_H
#define JSON_H


// Extracts a field from a JSON string.
// Parameters:
// - json: JSON string to search.
// - key: Key to search for in the JSON string.
// Returns:
//   A malloc'd null-terminated string with the value of the key, or NULL on
//   failure. Caller must free().
char* get_json_field(const char* json, const char* key);


// Unescapes a JSON-encoded string.
// Converts "\\n" to newline, "\\r" to CR, "\\\\" to "\\", others as-is.
// Parameters:
// - s: JSON-encoded string to unescape.
// Returns:
//   A malloc'd null-terminated string with the unescaped value, or NULL on
//   failure. Caller must free().
char* unescape_json(const char* s);


#endif // JSON_H