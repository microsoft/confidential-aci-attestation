/*
 * Simple implementation of COSE_Sign1 structure check.
 */
#include "cose.h"
#include "json.h"
#include "cert_chain.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "t_cose/t_cose_sign1_verify.h"
#include "qcbor/qcbor_decode.h"
#include "qcbor/qcbor_spiffy_decode.h"
#include "t_cose/q_useful_buf.h"


int verify_cose_sign1_signature(const COSE_Sign1* cose_sign1) {

    EVP_PKEY* leaf_pubkey = X509_get_pubkey(cert_chain_get_cert(cose_sign1->protected_header->x5_chain, 0));

    struct t_cose_key cose_pubkey = {0};
    cose_pubkey.k.key_ptr = leaf_pubkey;
    cose_pubkey.crypto_lib = 1; // 1 = OpenSSL, see t_cose_key definition

    struct t_cose_sign1_verify_ctx verify_ctx;
    struct q_useful_buf_c cose_message = { .ptr = cose_sign1->raw->ptr, .len = cose_sign1->raw->len };
    struct q_useful_buf_c payload;
    enum t_cose_err_t result;

    t_cose_sign1_verify_init(&verify_ctx, 0);
    t_cose_sign1_set_verification_key(&verify_ctx, cose_pubkey);
    result = t_cose_sign1_verify(&verify_ctx, cose_message, &payload, NULL);
    EVP_PKEY_free(leaf_pubkey);
    if (result == T_COSE_SUCCESS) {
        return 0; // Signature valid
    } else {
        fprintf(stderr, "✘ COSE_Sign1 signature verification failed: %d\n", result);
        return 1;
    }
}

static int parse_protected_header(UsefulBufC* msg, COSE_Sign1* cose_sign1) {

    cose_sign1->protected_header = malloc(sizeof(COSE_Sign1_Protected_Header));
    if (!cose_sign1->protected_header) {
        fprintf(stderr, "✘ Failed to allocate memory for COSE_Sign1 protected header\n");
        return 1;
    }
    memset(cose_sign1->protected_header, 0, sizeof(COSE_Sign1_Protected_Header));

    QCBORDecodeContext protected_header_ctx;
    QCBORDecode_Init(&protected_header_ctx, *msg, QCBOR_DECODE_MODE_NORMAL);

    QCBORDecode_EnterArray(&protected_header_ctx, NULL);
    QCBORDecode_GetNthTagOfLast(&protected_header_ctx, 0);
    struct q_useful_buf_c protected_parameters;
    QCBORDecode_EnterBstrWrapped(&protected_header_ctx, QCBOR_TAG_REQUIREMENT_NOT_A_TAG, &protected_parameters);
    QCBORDecode_EnterMap(&protected_header_ctx, NULL);
    enum
    {
      ALG_INDEX,
      CONTENT_TYPE_INDEX,
      X5_CHAIN_INDEX,
      ISS_INDEX,
      FEED_INDEX,
      END_INDEX
    };
    QCBORItem header_items[END_INDEX + 1];
    memset(header_items, 0, sizeof(header_items));
    header_items[ALG_INDEX].label.int64 = 1;
    header_items[ALG_INDEX].uLabelType = QCBOR_TYPE_INT64;
    header_items[ALG_INDEX].uDataType = QCBOR_TYPE_INT64;
    header_items[CONTENT_TYPE_INDEX].label.int64 = 3;
    header_items[CONTENT_TYPE_INDEX].uLabelType = QCBOR_TYPE_INT64;
    header_items[CONTENT_TYPE_INDEX].uDataType = QCBOR_TYPE_TEXT_STRING;
    header_items[X5_CHAIN_INDEX].label.int64 = 33;
    header_items[X5_CHAIN_INDEX].uLabelType = QCBOR_TYPE_INT64;
    header_items[X5_CHAIN_INDEX].uDataType = QCBOR_TYPE_ANY;
    header_items[ISS_INDEX].label.string = UsefulBuf_FromSZ("iss");
    header_items[ISS_INDEX].uLabelType = QCBOR_TYPE_TEXT_STRING;
    header_items[ISS_INDEX].uDataType = QCBOR_TYPE_TEXT_STRING;
    header_items[FEED_INDEX].label.string = UsefulBuf_FromSZ("feed");
    header_items[FEED_INDEX].uLabelType = QCBOR_TYPE_TEXT_STRING;
    header_items[FEED_INDEX].uDataType = QCBOR_TYPE_TEXT_STRING;
    header_items[END_INDEX].uLabelType = QCBOR_TYPE_NONE;
    QCBORDecode_GetItemsInMap(&protected_header_ctx, header_items);

    if (header_items[ALG_INDEX].uDataType != QCBOR_TYPE_NONE)
        cose_sign1->protected_header->alg = header_items[ALG_INDEX].val.int64;

    if (header_items[X5_CHAIN_INDEX].uDataType == QCBOR_TYPE_ARRAY) {
        QCBORDecode_EnterArrayFromMapN(&protected_header_ctx, header_items[X5_CHAIN_INDEX].label.int64);
        cose_sign1->protected_header->x5_chain = cert_chain_new();
        int result = QCBOR_SUCCESS;
        while (result != QCBOR_ERR_NO_MORE_ITEMS) {
            QCBORItem item;
            result = QCBORDecode_GetNext(&protected_header_ctx, &item);
            if ((result != QCBOR_SUCCESS && result != QCBOR_ERR_NO_MORE_ITEMS)) {
                fprintf(stderr, "✘ Failed to parse UVM endorsements cert chain\n");
                return 1;
            }
            if (item.uDataType == QCBOR_TYPE_BYTE_STRING) {
                cert_chain_add_der(
                    cose_sign1->protected_header->x5_chain,
                    (const uint8_t*)item.val.string.ptr,
                    item.val.string.len
                );
            }
        }
        QCBORDecode_ExitArray(&protected_header_ctx);
    }

    if (header_items[ISS_INDEX].uDataType != QCBOR_TYPE_NONE) {
        cose_sign1->protected_header->iss = malloc(header_items[ISS_INDEX].val.string.len + 1);
        memcpy(cose_sign1->protected_header->iss,  // NOLINT(clang-analyzer-security.insecureAPI.DeprecatedOrUnsafeBufferHandling)
               header_items[ISS_INDEX].val.string.ptr,
               header_items[ISS_INDEX].val.string.len);
        cose_sign1->protected_header->iss[header_items[ISS_INDEX].val.string.len] = '\0';
    }

    if (header_items[FEED_INDEX].uDataType != QCBOR_TYPE_NONE) {
        cose_sign1->protected_header->feed = malloc(header_items[FEED_INDEX].val.string.len + 1);
        memcpy(cose_sign1->protected_header->feed,  // NOLINT(clang-analyzer-security.insecureAPI.DeprecatedOrUnsafeBufferHandling)
               header_items[FEED_INDEX].val.string.ptr,
               header_items[FEED_INDEX].val.string.len);
        cose_sign1->protected_header->feed[header_items[FEED_INDEX].val.string.len] = '\0';
    }

    QCBORDecode_ExitMap(&protected_header_ctx);
    QCBORDecode_ExitBstrWrapped(&protected_header_ctx);
    QCBORDecode_Finish(&protected_header_ctx);

    return 0;
}

static int parse_payload(UsefulBufC* msg, COSE_Sign1* cose_sign1) {

    QCBORDecodeContext ctx;
    QCBORDecode_Init(&ctx, *msg, QCBOR_DECODE_MODE_NORMAL);

    // Get the COSE Sign1 Object
    QCBORItem cose_qcbor_item;
    QCBORDecode_VGetNext(&ctx, &cose_qcbor_item);
    if (
        cose_qcbor_item.uDataType != QCBOR_TYPE_ARRAY ||
        cose_qcbor_item.uTags[0] != CBOR_TAG_COSE_SIGN1 ||
        cose_qcbor_item.val.uCount != 4
    ) {
        fprintf(stderr, "✘ QCBOR Structure isn't a COSE Sign1 Document\n");
        return 1;
    }

    // Get the fields from the COSE Sign1 Object
    QCBORItem payload, tmp;
    QCBORDecode_EnterArray(&ctx, NULL);
    QCBORDecode_GetNext(&ctx, &tmp); // protected header
    QCBORDecode_GetNext(&ctx, &tmp); // unprotected header
    QCBORDecode_GetNext(&ctx, &payload);

    if (payload.uDataType != QCBOR_TYPE_BYTE_STRING) {
        fprintf(stderr, "✘ COSE_Sign1 payload failed to parse\n");
        return 1;
    }

    cose_sign1->payload = malloc(payload.val.string.len + 1);
    memcpy(cose_sign1->payload, payload.val.string.ptr, payload.val.string.len);
    cose_sign1->payload[payload.val.string.len] = '\0';

    QCBORDecode_ExitArray(&ctx);
    QCBORDecode_Finish(&ctx);

    return 0;
}


COSE_Sign1* cose_sign1_new(const uint8_t* buf, size_t len) {

    if (buf == NULL || len == 0) {
        fprintf(stderr, "✘ uvm_endorsements buffer is null or empty\n");
        return NULL;
    }

    COSE_Sign1* cose_sign1 = malloc(sizeof(COSE_Sign1));
    if (!cose_sign1) {
        fprintf(stderr, "✘ Failed to allocate memory for COSE_Sign1 structure\n");
        return NULL;
    }
    memset(cose_sign1, 0, sizeof(COSE_Sign1));

    cose_sign1->raw = malloc(sizeof(UsefulBufC));
    if (!cose_sign1->raw) {
        fprintf(stderr, "✘ Failed to allocate memory for COSE_Sign1 raw buffer\n");
        cose_sign1_free(cose_sign1);
        return NULL;
    }
    cose_sign1->raw->ptr = buf;
    cose_sign1->raw->len = len;

    if (parse_payload(cose_sign1->raw, cose_sign1) != 0) {
        cose_sign1_free(cose_sign1);
        return NULL;
    }

    if (parse_protected_header(cose_sign1->raw, cose_sign1) != 0) {
        cose_sign1_free(cose_sign1);
        return NULL;
    }

    return cose_sign1;
}

void cose_sign1_free(COSE_Sign1* cose_sign1) {
    if (cose_sign1) {
        if (cose_sign1->protected_header) {
            free(cose_sign1->protected_header->iss);
            free(cose_sign1->protected_header->feed);
            cert_chain_free(cose_sign1->protected_header->x5_chain);
            free(cose_sign1->protected_header);
        }
        free(cose_sign1->payload);
        free(cose_sign1->raw);
        free(cose_sign1);
    }
}