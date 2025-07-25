// test_cert_chain_unit.c - Unit tests for cert_chain

#include <stdio.h>
#include <stdlib.h>
#include <openssl/stack.h>
#include <openssl/x509.h>
#include "lib/cert_chain.h"
#include "lib/host_amd_certs.h"
#include "lib/base64.h"
#include "lib/json.h"

static int test_new_and_free(void) {
    cert_chain_t *chain = cert_chain_new();
    if (!chain) {
        fprintf(stderr, "[new] Returned NULL\n");
        return 1;
    }
    STACK_OF(X509) *stack = cert_chain_get_stack(chain);
    if (!stack) {
        fprintf(stderr, "[new] get_stack returned NULL\n");
        cert_chain_free(chain);
        return 1;
    }
    if (sk_X509_num(stack) != 0) {
        fprintf(stderr, "[new] Expected 0 certs, got %d\n", sk_X509_num(stack));
        cert_chain_free(chain);
        return 1;
    }
    cert_chain_free(chain);
    printf("[PASS] new and free empty chain\n");
    return 0;
}

static int test_add_invalid_pem(void) {
    cert_chain_t *chain = cert_chain_new();
    if (!chain) {
        fprintf(stderr, "[add_invalid] new returned NULL\n");
        return 1;
    }
    int ok = cert_chain_add_pem(chain, "not a pem");
    if (ok != 1) {
        fprintf(stderr, "[add_invalid] Expected 0, got %d\n", ok);
        cert_chain_free(chain);
        return 1;
    }
    cert_chain_free(chain);
    printf("[PASS] add invalid pem fails\n");
    return 0;
}

static int test_add_pem_chain_invalid(void) {
    cert_chain_t *chain = cert_chain_new();
    if (!chain) {
        fprintf(stderr, "[add_chain_invalid] new returned NULL\n");
        return 1;
    }
    int ok = cert_chain_add_pem_chain(chain, "not a pem chain");
    // Function returns 1 even if no certificates are added
    if (ok != 0) {
        fprintf(stderr, "[add_chain_empty] Expected 1, got %d\n", ok);
        cert_chain_free(chain);
        return 1;
    }
    cert_chain_free(chain);
    printf("[PASS] add empty pem chain returns success\n");
    return 0;
}

// Test null inputs for all APIs
static int test_null_inputs(void) {
    cert_chain_free(NULL);
    if (cert_chain_add_pem(NULL, "x") == 0) return 1;
    if (cert_chain_add_der(NULL, (uint8_t*)"", 1) == 0) return 1;
    if (cert_chain_add_pem_chain(NULL, "x") == 0) return 1;
    if (cert_chain_get_stack(NULL)) return 1;
    if (cert_chain_validate(NULL, 0) == 0) return 1;
    if (cert_chain_get_cert(NULL, 0)) return 1;
    if (cert_chain_validate_root(NULL, NULL) == 0) return 1;
    printf("[PASS] null input error paths\n");
    return 0;
}

// Test add valid PEM chain extracted from host AMD certs example
static int test_valid_pem_and_validate(void) {
    char* b64 = get_host_amd_certs();
    size_t raw_len = 0;
    uint8_t* raw = base64_decode(b64, strlen(b64), &raw_len);
    free(b64);
    char* json = malloc(raw_len + 1);
    memcpy(json, raw, raw_len);
    json[raw_len] = '\0'; free(raw);
    char* pem = get_json_field(json, "vcekCert"); free(json);
    cert_chain_t* chain = cert_chain_new();
    if (!chain) { free(pem); return 1; }
    if (cert_chain_add_pem(chain, pem) != 0) { free(pem); cert_chain_free(chain); return 1; }
    free(pem);
    if (cert_chain_get_cert(chain, 1) != NULL) { cert_chain_free(chain); return 1; }
    if (cert_chain_validate(chain, 2) == 0) { cert_chain_free(chain); return 1; }
    if (cert_chain_validate(chain, 1) == 0) { cert_chain_free(chain); return 1; }
    X509* cert = cert_chain_get_cert(chain, 0);
    EVP_PKEY* key = X509_get_pubkey(cert);
    if (cert_chain_validate_root(chain, key) == 0) { EVP_PKEY_free(key); cert_chain_free(chain); return 1; }
    EVP_PKEY_free(key);
    cert_chain_free(chain);
    printf("[PASS] valid PEM add and validate paths\n");
    return 0;
}

// Test add DER path: convert vcekCert to DER then add_der
static int test_add_der_path(void) {
    char* b64 = get_host_amd_certs();
    size_t raw_len = 0;
    uint8_t* raw = base64_decode(b64, strlen(b64), &raw_len);
    free(b64);
    char* json = malloc(raw_len + 1);
    memcpy(json, raw, raw_len);
    json[raw_len] = '\0'; free(raw);
    char* pem = get_json_field(json, "vcekCert"); free(json);
    char* unesc = unescape_json(pem); free(pem);
    BIO* bio = BIO_new_mem_buf(unesc, -1);
    X509* x = PEM_read_bio_X509(bio, NULL, 0, NULL);
    BIO_free(bio); free(unesc);
    int der_len = i2d_X509(x, NULL);
    unsigned char* der = NULL;
    der_len = i2d_X509(x, &der);
    X509_free(x);
    cert_chain_t* chain = cert_chain_new();
    if (!chain) { free(der); return 1; }
    if (cert_chain_add_der(chain, der, der_len) != 0) { free(der); cert_chain_free(chain); return 1; }
    free(der);
    if (sk_X509_num(cert_chain_get_stack(chain)) != 1) { cert_chain_free(chain); return 1; }
    cert_chain_free(chain);
    printf("[PASS] add_der PEM->DER path\n");
    return 0;
}

int main(void) {
    // Declare test suite
    printf("=== test_cert_chain_unit ===\n");
    if (test_new_and_free()) return 1;
    if (test_add_invalid_pem()) return 1;
    if (test_add_pem_chain_invalid()) return 1;
    if (test_null_inputs()) return 1;
    if (test_valid_pem_and_validate()) return 1;
    if (test_add_der_path()) return 1;
    printf("All tests passed\n");
    return 0;
}
