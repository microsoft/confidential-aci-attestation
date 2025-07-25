#ifndef FILES_H
#define FILES_H

// Reads the contents of a file into a null-terminated string.
// Parameters:
// - path: Path to the file, can be either absolute or relative to process cwd.
// Returns:
//   A malloc'd null-terminated buffer with the file contents, or NULL on
//   failure. Caller must free().
char* read_file(const char* path);

#endif // FILES_H