#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include "lib/snp_report.h"
#include "lib/base64.h"
#include "lib/json.h"
#include "lib/cert_chain.h"
#include "lib/verification.h"
#include "lib/cose.h"
#include <openssl/stack.h>
#include <ctype.h>
#include <openssl/evp.h>

int main(int argc, char** argv) {

    // Initialize parameters
    snp_report_data_t report_data = {0};
    char* security_policy_b64 = NULL;
    char* ccf_attestation = NULL;

    // Parse parameters to the script
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--report-data") == 0 && i + 1 < argc) {

            // Get File Descriptor
            FILE* f = fopen(argv[++i], "rb");
            if (!f) {
                perror("fopen report_data");
                return 1;
            }

            // Read the report data
            fread(report_data, 1, sizeof(report_data), f);
            fclose(f);
        }
        else if (strcmp(argv[i], "--security-policy-b64") == 0 && i + 1 < argc) {
            security_policy_b64 = argv[++i];
        }
        else if (argv[i][0] != '-' && ccf_attestation == NULL) {
            ccf_attestation = argv[i];
        }
    }

    // Check for correct usage, otherwise print usage
    if (!security_policy_b64 || !ccf_attestation) {
        fprintf(stderr, "Usage: %s \n", argv[0]);
        fprintf(stderr, "Verify SNP report from CCF attestation\n");
        fprintf(stderr, "Parameters:\n");
        fprintf(stderr, "  [ccf_attestation] \n");
        fprintf(stderr, "  --report-data <string> \n");
        fprintf(stderr, "  --security-policy-b64 <string> \n");
        return 1;
    }

    // Parse SNP report from input JSON
    SnpReport snp_report = {0};
    char* evidence = get_json_field(ccf_attestation, "evidence");
    uint8_t* snp_report_decoded = base64_decode(evidence, strlen(evidence), NULL);
    free(evidence);
    if (!snp_report_decoded) {
        fprintf(stderr, "Failed to decode or invalid SNP report size\n");
        free(snp_report_decoded);
        return 1;
    }
    memcpy(&snp_report, snp_report_decoded, sizeof(SnpReport));
    free(snp_report_decoded);

    // Parse the endorsements
    char* endorsements = get_json_field(ccf_attestation, "endorsements");
    uint8_t* endorsements_decoded = base64_decode(endorsements, strlen(endorsements), NULL);
    if (!endorsements_decoded) {
        fprintf(stderr, "Failed to decode endorsements\n");
        free(endorsements);
        return 1;
    }
    free(endorsements);

    // Parse the certificate chain
    char* vcek_cert_pem = get_json_field((char*)endorsements_decoded, "vcekCert");
    char* certificate_chain_pem = get_json_field((char*)endorsements_decoded, "certificateChain");
    free(endorsements_decoded);
    cert_chain_t* certificate_chain = cert_chain_new();
    if (!certificate_chain) {
        fprintf(stderr, "Failed to create certificate chain object\n");
        free(vcek_cert_pem);
        free(certificate_chain_pem);
        return 1;
    }
    if (cert_chain_add_pem(certificate_chain, vcek_cert_pem) != 0) {
        fprintf(stderr, "Failed to add VCEK certificate to chain\n");
        free(vcek_cert_pem);
        free(certificate_chain_pem);
        cert_chain_free(certificate_chain);
        return 1;
    }
    free(vcek_cert_pem);
    if (cert_chain_add_pem_chain(certificate_chain, certificate_chain_pem) != 0) {
        fprintf(stderr, "Failed to append certificate chain\n");
        free(certificate_chain_pem);
        cert_chain_free(certificate_chain);
        return 1;
    }
    free(certificate_chain_pem);

    // Run checks
    if (verify_snp_report_is_genuine(&snp_report, certificate_chain) != 0) {
        cert_chain_free(certificate_chain);
        return 1;
    }
    cert_chain_free(certificate_chain);

    if (verify_snp_report_has_report_data(&snp_report, &report_data) != 0) {
        return 1;
    }

    if (verify_snp_report_has_security_policy(&snp_report, security_policy_b64) != 0) {
        return 1;
    }

    // Parse the utility VM build COSE from uvm_endorsements
    // Extract uvm_endorsements base64 from attestation JSON
    char* uvm_endorsements_b64 = get_json_field(ccf_attestation, "uvm_endorsements");
    if (!uvm_endorsements_b64) {
        fprintf(stderr, "✘ Missing uvm_endorsements in attestation JSON\n");
        return 1;
    }
    // Trim whitespace
    char* p = uvm_endorsements_b64;
    while (*p && isspace((unsigned char)*p)) p++;
    char* end = uvm_endorsements_b64 + strlen(uvm_endorsements_b64);
    while (end > p && isspace((unsigned char)*(end - 1))) end--;
    size_t trim_len = end - p;
    size_t cose_len = 0;
    uint8_t* cose_buf = base64_decode(p, trim_len, &cose_len);
    free(uvm_endorsements_b64);
    if (!cose_buf) {
        fprintf(stderr, "✘ Failed to decode uvm_endorsements base64\n");
        return 1;
    }

    // Get COSE_Sign1 object
    COSE_Sign1* uvm_endorsement = cose_sign1_new(cose_buf, cose_len);
    if (!uvm_endorsement) {
        fprintf(stderr, "✘ Failed to parse COSE_Sign1\n");
        return 1;
    }

    if (verify_utility_vm_build(&snp_report, uvm_endorsement) != 0) {
        cose_sign1_free(uvm_endorsement);
        free(cose_buf);
        return 1;
    }
    cose_sign1_free(uvm_endorsement);
    free(cose_buf);

    fprintf(stderr, "\n----------------------------------------------------\n");
    fprintf(stderr, "\nFinal Results:\n");
    fprintf(stderr, "✔ SNP Report comes from genuine AMD hardware\n");
    fprintf(stderr, "✔ SNP Report has the expected report data\n");
    fprintf(stderr, "✔ SNP Report has the expected security policy\n");
    fprintf(stderr, "✔ SNP Report utility VM measurement is endorsed by Microsoft\n");
    fprintf(stderr, "\nAttestation validation successful\n");
    return 0;
}