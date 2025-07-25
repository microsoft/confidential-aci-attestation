#include "snp_report.h"
#include "base64.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <errno.h>
#include <stdint.h>
#include "embedded_examples.h"
#include "files.h"  // retained for other paths

#include "hex.h"
#include <ctype.h>
#include <stdlib.h>
#include <stdio.h>


static int get_snp_report_sev_guest(uint8_t* report_data, SnpReport* out_report) {

    int fd = open("/dev/sev-guest", O_RDWR | O_CLOEXEC);
    if (fd < 0) return -1;

    // Create SNP Request
    SnpRequest snp_request = {0};

    // Copy report_data into request
    for (size_t i = 0; i < sizeof(snp_request.report_data); i++) {
        snp_request.report_data[i] = report_data[i];
    }

    // Create SNP Response
    SnpIoctlResponse snp_ioctl_response = {0};
    SnpResponse snp_response = {0};

    // Create IOCTL Payload
    SevGuestIoctlRequest ioctl_request = {
        .msg_version = 1,
        .req_data = (uint64_t)&snp_request,
        .resp_data = (uint64_t)&snp_ioctl_response,
        .fw_err = 0
    };

    // Call IOCTL
    int rc = ioctl(fd, SEV_GUEST_GET_REPORT, &ioctl_request);
    if (rc < 0) {
        fprintf(stderr, "Failed to issue ioctl SEV_SNP_GUEST_MSG_REPORT\n");
        close(fd);
        return -1;
    }

    // Parse out IOCTL response
    // Copy entire IOCTL response into snp_response
    {
        unsigned char *src = (unsigned char *)snp_ioctl_response.data;
        unsigned char *dst = (unsigned char *)&snp_response;
        for (size_t i = 0; i < sizeof(SnpResponse); i++) {
            dst[i] = src[i];
        }
    }
    // Extract the report
    {
        unsigned char *src = (unsigned char *)&snp_response.report;
        unsigned char *dst = (unsigned char *)out_report;
        for (size_t i = 0; i < sizeof(SnpReport); i++) {
            dst[i] = src[i];
        }
    }

    close(fd);
    return 0;
}


static int get_snp_report_sev(uint8_t* report_data, SnpReport* out_report) {
    int fd = open("/dev/sev", O_RDWR | O_CLOEXEC);
    if (fd < 0) return -1;

    // Create SNP Request
    SnpRequest snp_request = {0};
    // Copy report_data into request
    for (size_t i = 0; i < sizeof(snp_request.report_data); i++) {
        snp_request.report_data[i] = report_data[i];
    }

    // Create SNP Response
    SnpIoctlResponse snp_ioctl_response = {0};
    SnpResponse snp_response = {0};

    // Create IOCTL Payload
    SevIoctlRequest ioctl_request = {
        .req_msg_type = SNP_MSG_REPORT_REQ,
        .rsp_msg_type = SNP_MSG_REPORT_RSP,
        .msg_version = 1,
        .request_len = sizeof(snp_request),
        .request_uaddr = (uint64_t) (void*) &snp_request,
        .response_len = sizeof(snp_ioctl_response),
        .response_uaddr = (uint64_t) (void*) &snp_ioctl_response,
        .error = 0
    };

    // Call IOCTL
    int rc = ioctl(fd, SEV_GUEST_GET_REPORT, &ioctl_request);
    if (rc < 0) {
        fprintf(stderr, "Failed to issue ioctl SEV_SNP_GUEST_MSG_REPORT\n");
        close(fd);
        return -1;
    }

    // Parse out IOCTL response
    // Copy entire IOCTL response into snp_response
    {
        unsigned char *src = (unsigned char *)snp_ioctl_response.data;
        unsigned char *dst = (unsigned char *)&snp_response;
        for (size_t i = 0; i < sizeof(SnpResponse); i++) {
            dst[i] = src[i];
        }
    }
    // Extract the report
    {
        unsigned char *src = (unsigned char *)&snp_response.report;
        unsigned char *dst = (unsigned char *)out_report;
        for (size_t i = 0; i < sizeof(SnpReport); i++) {
            dst[i] = src[i];
        }
    }

    close(fd);
    return 0;
}


static int get_snp_report_virtual(SnpReport* out_report) {
    size_t b64_len = snp_report_b64_end - snp_report_b64_start;
    size_t raw_len = 0;

    uint8_t* raw = base64_decode(
        (const char*)snp_report_b64_start,
        b64_len,
        &raw_len
    );
    if (!raw || raw_len < sizeof(SnpReport)) {
        free(raw);
        return -1;
    }

    // Copy virtual report data
    {
        unsigned char *src = raw;
        unsigned char *dst = (unsigned char *)out_report;
        for (size_t i = 0; i < sizeof(SnpReport); i++) {
            dst[i] = src[i];
        }
    }
    free(raw);
    return 0;
}


int get_snp_report(uint8_t* report_data, SnpReport* out_report) {
    if (!out_report) return -1;

    if (get_snp_report_sev_guest(report_data, out_report) == 0) {
        return 0;
    }

    if (get_snp_report_sev(report_data, out_report) == 0)
        return 0;

    return get_snp_report_virtual(out_report);
}


char* format_report_data(const uint8_t* data, size_t length) {
    if (!data) return NULL;

    // Determine printable ASCII length and if the data is ASCII
    size_t ascii_len = 0;
    while (ascii_len < length && data[ascii_len] != '\0' && isprint(data[ascii_len])) {
        ascii_len++;
    }
    bool is_ascii = ascii_len > 0;

    // Construct the length of the output string
    size_t output_len = 0;
    output_len += length * 2;                     // 2 hex chars per byte
    output_len += (length > 0 ? length - 1 : 0);  // 1 space or newline per byte
    if (is_ascii) output_len += ascii_len + 3;    // ASCII chars, parentheses and newline
    output_len += 1;                              // null terminator

    // Allocate the output string
    char* output = malloc(output_len);
    if (!output) return NULL;
    char* output_ptr = output;

    // Print the hex data
    static const char hex_digits[] = "0123456789abcdef";
    static const size_t bytes_per_line = 16;
    for (size_t i = 0; i < length; i++) {
        uint8_t byte = data[i];
        *output_ptr++ = hex_digits[(byte >> 4) & 0xF];
        *output_ptr++ = hex_digits[byte & 0xF];
        if (i + 1 < length) {
            if ((i + 1) % bytes_per_line == 0) *output_ptr++ = '\n';
            else *output_ptr++ = ' ';
        }
    }

    // Print the ASCII data if applicable
    if (is_ascii) {
        *output_ptr++ = '\n';
        *output_ptr++ = '(';
        for (size_t i = 0; i < ascii_len; i++) {
            *output_ptr++ = data[i];
        }
        *output_ptr++ = ')';
    }

    *output_ptr = '\0';  // Null-terminate the string

    return output;
}


uint8_t* remove_signature(SnpReport* snp_report) {
    if (!snp_report) return NULL;

    // Allocate memory for the report without the signature
    size_t signature_offset = offsetof(SnpReport, signature);
    uint8_t* report_without_signature = malloc(signature_offset);
    if (!report_without_signature) return NULL;

    // Copy the report data without the signature
    memcpy(report_without_signature, snp_report, signature_offset);

    return report_without_signature;
}


ECDSA_SIG* parse_signature(const Signature* signature) {

    BIGNUM* r = BN_lebin2bn(signature->r, 72, NULL);
    BIGNUM* s = BN_lebin2bn(signature->s, 72, NULL);
    if (!r || !s) {
        fprintf(stderr, "✘ Failed to extract r,s from signature\n");
        if(r) BN_free(r);
        if(s) BN_free(s);
        return NULL;
    }

    ECDSA_SIG* ecdsa_sig = ECDSA_SIG_new();
    if (!ecdsa_sig) {
        fprintf(stderr, "✘ Failed to allocate ECDSA_SIG\n");
        BN_free(r);
        BN_free(s);
        return NULL;
    }

    if (ECDSA_SIG_set0(ecdsa_sig, r, s) != 1) {
        fprintf(stderr, "✘ Failed to set r and s in ECDSA_SIG\n");
        ECDSA_SIG_free(ecdsa_sig);
        return NULL;
    }

    return ecdsa_sig;
}
