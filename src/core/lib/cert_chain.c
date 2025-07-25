#include "cert_chain.h"
#include "json.h"
#include "sha256.h"
#include "snp_report.h"
#include <stdlib.h>
#include <string.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/stack.h>
#include <openssl/x509.h>


struct cert_chain {
    STACK_OF(X509)* stack;
};


cert_chain_t* cert_chain_new(void) {
    cert_chain_t* chain = malloc(sizeof(*chain));
    if (!chain) return NULL;

    chain->stack = sk_X509_new_null();

    if (!chain->stack) {
        free(chain);
        return NULL;
    }

    return chain;
}


void cert_chain_free(cert_chain_t* chain) {
    if (!chain) return;

    if (chain->stack) {
        while (sk_X509_num(chain->stack) > 0) {
            X509* cert = sk_X509_pop(chain->stack);
            X509_free(cert);
        }
        sk_X509_free(chain->stack);
    }

    free(chain);
}


int cert_chain_add_pem(cert_chain_t* chain, const char* pem) {
    if (!chain || !pem) return 1;

    char* unescaped_pem = unescape_json(pem);
    if (!unescaped_pem) return 1;

    BIO* bio = BIO_new_mem_buf(unescaped_pem, -1);
    if (!bio) {
        free(unescaped_pem);
        return 1;
    }

    X509* cert = PEM_read_bio_X509(bio, NULL, 0, NULL);
    BIO_free(bio);
    free(unescaped_pem);

    if (!cert) return 1;
    if (!sk_X509_push(chain->stack, cert)) {
        X509_free(cert);
        return 1;
    }

    return 0;
}


int cert_chain_add_der(cert_chain_t* chain, const uint8_t* der, size_t der_len) {
    if (!chain || !der || der_len == 0) return 1;

    const unsigned char* p = der;
    X509* cert = d2i_X509(NULL, &p, der_len);
    if (!cert) return 1;
    if (!sk_X509_push(chain->stack, cert)) {
        X509_free(cert);
        return 1;
    }
    return 0;
}


int cert_chain_add_pem_chain(cert_chain_t* chain, const char* pem_chain) {
    if (!chain || !pem_chain) return 1;

    char* unescaped_pem_chain = unescape_json(pem_chain);
    if (!unescaped_pem_chain) return 1;
    const char* begin_marker = "-----BEGIN CERTIFICATE-----";
    const char* unescaped_pem_chain_ptr = unescaped_pem_chain;

    int ok = 0;
    while ((unescaped_pem_chain_ptr = strstr(unescaped_pem_chain_ptr, begin_marker))) {

        const char* start = unescaped_pem_chain_ptr;

        const char* end = strstr(start, "-----END CERTIFICATE-----");
        if (!end) { ok = 0; break; }

        end += strlen("-----END CERTIFICATE-----");

        const char* unescaped_pem_chain_ptr_end = end;
        while (*unescaped_pem_chain_ptr_end == '\r' || *unescaped_pem_chain_ptr_end == '\n') unescaped_pem_chain_ptr_end++;

        size_t len = unescaped_pem_chain_ptr_end - start;
        char* cert = malloc(len + 1);
        if (!cert) { ok = 0; break; }

        for (size_t j = 0; j < len; j++) {
            cert[j] = start[j];
        }
        cert[len] = '\0';

        if (!cert_chain_add_pem(chain, cert)) ok = 0;

        free(cert);
        unescaped_pem_chain_ptr = unescaped_pem_chain_ptr_end;
    }
    free(unescaped_pem_chain);
    return ok;
}


STACK_OF(X509)* cert_chain_get_stack(const cert_chain_t* chain) {
    if (!chain) return NULL;
    return chain->stack;
}


int cert_chain_validate(const cert_chain_t* chain, size_t expected_cert_count) {
    if (!chain) return 1;

    // Get the stack of certificates
    STACK_OF(X509)* stack = cert_chain_get_stack(chain);
    if (!stack) return 1;

    // Check the number of certificates
    int num = sk_X509_num(stack);
    if (num <= 0) return 1;
    if ((size_t)num != expected_cert_count) return 1;

    // Verify each cert is signed by its issuer (next cert in the stack)
    for (int i = 0; i < num - 1; i++) {
        X509* cert = sk_X509_value(stack, i);
        X509* issuer = sk_X509_value(stack, i + 1);
        EVP_PKEY* key = X509_get_pubkey(issuer);
        if (!key) return 1;
        int ok = X509_verify(cert, key);
        EVP_PKEY_free(key);
        if (ok <= 0) return 1;
    }

    // Verify the last certificate is self-signed
    X509* last = sk_X509_value(stack, num - 1);
    EVP_PKEY* root_key = X509_get_pubkey(last);
    if (!root_key) return 1;
    int root_ok = X509_verify(last, root_key);
    EVP_PKEY_free(root_key);
    return (root_ok > 0 ? 0 : 1);
}


X509* cert_chain_get_cert(const cert_chain_t* chain, size_t index) {
    if (!chain) return NULL;
    STACK_OF(X509)* stack = cert_chain_get_stack(chain);
    if (!stack) return NULL;
    int num = sk_X509_num(stack);
    if (index >= (size_t)num) return NULL;
    return sk_X509_value(stack, index);
}


int cert_chain_validate_root(const cert_chain_t* chain, EVP_PKEY* trusted_root_pubkey) {
    if (!chain || !trusted_root_pubkey) return 1;
    STACK_OF(X509)* stack = cert_chain_get_stack(chain);
    if (!stack) return 1;
    int num = sk_X509_num(stack);
    if (num <= 0) return 1;
    X509* root = sk_X509_value(stack, num - 1);
    if (!root) return 1;
    // Verify root certificate signature with provided public key
    int ok = X509_verify(root, trusted_root_pubkey);
    return (ok > 0 ? 0 : 1);
}


EVP_PKEY* pem_to_pub_key(const char* pem) {
    if (!pem) return NULL;

    char* unescaped_pem = unescape_json(pem);
    if (!unescaped_pem) return NULL;

    BIO* bio = BIO_new_mem_buf(unescaped_pem, -1);
    if (!bio) {
        free(unescaped_pem);
        return NULL;
    }

    EVP_PKEY* key = PEM_read_bio_PUBKEY(bio, NULL, 0, NULL);
    BIO_free(bio);

    free(unescaped_pem);
    return key;
}


// Frees a public key loaded by pubkey_from_pem(). Safe to call with NULL.
void pub_key_free(EVP_PKEY* key) {
    if (key) EVP_PKEY_free(key);
}


int cert_chain_validate_signature(cert_chain_t* chain, const Signature* signature, const uint8_t* data) {
    if (!chain || !signature || !data) return 1;

    // Get the stack of certificates
    STACK_OF(X509)* stack = cert_chain_get_stack(chain);
    if (!stack) return 1;

    // Get the first certificate (VCEK)
    X509* vcek_cert = sk_X509_value(stack, 0);
    if (!vcek_cert) return 1;

    // Get the public key from the VCEK certificate
    EVP_PKEY* vcek_pubkey = X509_get_pubkey(vcek_cert);
    if (!vcek_pubkey) return 1;

    // Hash the data using SHA-384
    uint8_t* digest = sha384(data, sizeof(data));
    if (!digest) {
        fprintf(stderr, "✘ Failed to calculate SHA-384 hash\n");
        EVP_PKEY_free(vcek_pubkey);
        return 1;
    }

    ECDSA_SIG* ecdsa_sig = parse_signature(signature);

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"

    // Get EC_KEY from EVP_PKEY
    EC_KEY* ec_key = EVP_PKEY_get1_EC_KEY(vcek_pubkey);
    if (!ec_key) {
        fprintf(stderr, "✘ Could not extract EC_KEY from VCEK public key\n");
        ECDSA_SIG_free(ecdsa_sig);
        EVP_PKEY_free(vcek_pubkey);
        return 1;
    }

    int verify_ok = ECDSA_do_verify(digest, 48, ecdsa_sig, ec_key);
    free(digest);

    ECDSA_SIG_free(ecdsa_sig);
    EC_KEY_free(ec_key);
    EVP_PKEY_free(vcek_pubkey);

#pragma GCC diagnostic pop


    return verify_ok == 1 ? 0 : 1;
}
