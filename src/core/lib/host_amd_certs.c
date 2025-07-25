#include "host_amd_certs.h"
#include "files.h"
#include "embedded_examples.h"
#include <glob.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>


static char* get_host_amd_certs_aci(void) {

    // Find the security context directory and the host AMD certs file
    glob_t g = {0};
    if (glob("/security-context-*/host-amd-cert-base64", 0, NULL, &g) != 0 || g.gl_pathc == 0) {
        globfree(&g);
        return NULL;
    }

    // Read the file into a string
    char* json = read_file(g.gl_pathv[0]);
    globfree(&g);

    return json;
}


static char* get_host_amd_certs_virtual(void) {

    // Allocate space for the base64 string
    size_t host_amd_certs_b64_len = host_amd_certs_b64_end - host_amd_certs_b64_start;
    char* host_amd_certs_b64 = malloc(host_amd_certs_b64_len + 1);
    if (!host_amd_certs_b64) {
        return NULL;
    }

    // Copy the base64 string from an embedded variable into the allocated space
    // This is so that callers can free just like they would for the ACI version
    for (size_t i = 0; i < host_amd_certs_b64_len; i++) {
        host_amd_certs_b64[i] = host_amd_certs_b64_start[i];
    }

    // Null-terminate the string
    host_amd_certs_b64[host_amd_certs_b64_len] = '\0';

    return host_amd_certs_b64;
}

char* get_host_amd_certs(void) {
    char* certs = get_host_amd_certs_aci();
    if (certs) return certs;
    return get_host_amd_certs_virtual();
}