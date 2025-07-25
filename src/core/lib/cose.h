/*
 * Simple COSE_Sign1 structure checker.
 * Provides a minimal check that a buffer is a COSE_Sign1 message by
 * verifying the CBOR tag and array header.
 */
#ifndef COSE_H
#define COSE_H

#include <stddef.h>
#include <stdint.h>
#include "qcbor/qcbor.h"
#include "cert_chain.h"

typedef struct {
    int64_t alg;
    char* content_type;
    cert_chain_t* x5_chain; // Pointer to a certificate chain
    char* iss;
    char* feed;
} COSE_Sign1_Protected_Header;

typedef struct {
    UsefulBufC* raw;
    COSE_Sign1_Protected_Header* protected_header;
    uint8_t* payload;
} COSE_Sign1;


/**
 * Get the payload from a COSE_Sign1 structure.
 * Returns a pointer to the payload, or NULL on failure.
 * The caller is responsible for freeing the returned pointer.
 */
COSE_Sign1* cose_sign1_new(const uint8_t* buf, size_t len);


/**
 * Frees the COSE_Sign1 structure and its components.
 */
void cose_sign1_free(COSE_Sign1* cose_sign1);


/**
 * Verifies the signature of a COSE_Sign1 structure.
 * Returns 0 if the signature is valid, or a non-zero value on failure.
 */
int verify_cose_sign1_signature(const COSE_Sign1* cose_sign1);


#endif // COSE_H

