#ifndef CERT_CHAIN_H
#define CERT_CHAIN_H

#include <stddef.h>
#include <openssl/stack.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include "snp_report.h"


// Opaque certificate chain structure
typedef struct cert_chain cert_chain_t;


// Creates a new, empty certificate chain. Returns NULL on failure.
// Caller must free with cert_chain_free().
cert_chain_t* cert_chain_new(void);


// Frees a certificate chain. Safe to call with NULL.
void cert_chain_free(cert_chain_t* chain);


// Adds a single PEM certificate to an existing chain.
int cert_chain_add_pem(cert_chain_t* chain, const char* pem);


// Adds a single DER certificate to an existing chain.
int cert_chain_add_der(cert_chain_t* chain, const uint8_t* der, size_t der_len);


// Parses one or more PEM certificates concatenated and adds them to the
// existing chain.
int cert_chain_add_pem_chain(cert_chain_t* chain, const char* pem_chain);


// Validates that each certificate in the chain is signed by the next certificate.
// The last certificate must be self-signed.
int cert_chain_validate(const cert_chain_t* chain, size_t expected_cert_count);


// Returns the certificate at the specified index in the chain.
// Returns NULL if the index is out of bounds or if the chain is NULL.
X509* cert_chain_get_cert(const cert_chain_t* chain, size_t index);


// Loads a public key from a PEM-formatted string (JSON-escaped allowed).
// Returns an EVP_PKEY* on success, or NULL on failure. Caller must free with pubkey_free().
// Requires <openssl/evp.h> and <openssl/pem.h> to be included by consumer.
EVP_PKEY* pem_to_pub_key(const char* pem);


// Validates that the root certificate in the chain is signed by the provided public key.
int cert_chain_validate_root(const cert_chain_t* chain, EVP_PKEY* trusted_root_pubkey);


// Returns the underlying OpenSSL STACK_OF(X509)* representing the certificate chain.
// Caller must not modify or free the returned stack. Returns NULL if chain is NULL.
STACK_OF(X509)* cert_chain_get_stack(const cert_chain_t* chain);


// Frees a public key loaded by pubkey_from_pem(). Safe to call with NULL.
void pub_key_free(EVP_PKEY* key);


// Validates the signature on some data comes from the certificate chain/
// Parameters:
// - chain: The certificate chain to validate against.
// - signature: The signature to validate.
// - data: The data that was signed.
// Returns: 0 if the signature is valid
int cert_chain_validate_signature(cert_chain_t* chain, const Signature* signature, const uint8_t* data);


#endif // CERT_CHAIN_H