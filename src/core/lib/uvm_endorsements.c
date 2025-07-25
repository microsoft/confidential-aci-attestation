#include "uvm_endorsements.h"
#include "files.h"
#include "embedded_examples.h"
#include <glob.h>
#include <stdlib.h>

// Try to read UVM endorsements from ACI security context directory
static char* get_uvm_endorsements_aci(void) {
    glob_t g = {0};
    if (glob("/security-context-*/reference-info-base64", 0, NULL, &g) != 0 || g.gl_pathc == 0) {
        globfree(&g);
        return NULL;
    }
    char* b64 = read_file(g.gl_pathv[0]);
    globfree(&g);
    return b64;
}

// Fallback to embedded example for virtual mode
static char* get_uvm_endorsements_virtual(void) {
    size_t len = reference_info_b64_end - reference_info_b64_start;
    char* b64 = malloc(len + 1);
    if (!b64) return NULL;
    for (size_t i = 0; i < len; i++) {
        b64[i] = reference_info_b64_start[i];
    }
    b64[len] = '\0';
    return b64;
}

// Public API: get UVM endorsements, either from ACI context or embedded example
char* get_uvm_endorsements(void) {
    char* r = get_uvm_endorsements_aci();
    if (r) return r;
    // Fallback to embedded example
    return get_uvm_endorsements_virtual();
}