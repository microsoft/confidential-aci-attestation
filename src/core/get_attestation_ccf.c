#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include "lib/snp_report.h"
#include "lib/host_amd_certs.h"
#include "lib/base64.h"
#include "lib/uvm_endorsements.h"

int main(int argc, char** argv) {

    // Prepare report_data
    snp_report_data_t report_data = {0};
    if (argc > 1 && argv[1]) {
        size_t input_len = strlen(argv[1]);
        if (input_len > sizeof(snp_report_data_t)) {
            fprintf(stderr, "Warning: report_data string too long (%zu > %zu), truncating.\n", input_len, sizeof(snp_report_data_t));
            input_len = sizeof(snp_report_data_t);
        }
        memcpy(report_data, argv[1], input_len);
    }

    // Get the SNP report
    SnpReport* snp_report = malloc(sizeof(SnpReport));
    if (!snp_report) {
        fprintf(stderr, "Allocation failure\n");
        return 1;
    }
    memset(snp_report, 0, sizeof(SnpReport));
    int ret = get_snp_report(report_data, snp_report);
    if (ret != 0) {
        fprintf(stderr, "Failed to get SNP report\n");
        free(snp_report);
        return 1;
    }

    // Base64 encode the SNP report
    size_t snp_report_b64_len = 0;
    char* snp_report_b64 = base64_encode((const uint8_t*)snp_report, sizeof(SnpReport), &snp_report_b64_len);
    free(snp_report);
    if (!snp_report_b64) {
        fprintf(stderr, "Failed to base64 encode\n");
        free(snp_report_b64);
        return 1;
    }

    // Get the Host AMD Certificates base64
    char* host_amd_certs_b64 = get_host_amd_certs();
    if (!host_amd_certs_b64) {
        fprintf(stderr, "Failed to load host AMD certificates\n");
        free(snp_report_b64);
        return 1;
    }

    // Get the UVM endorsements base64
    char* uvm_endorsements_b64 = get_uvm_endorsements();
    if (!uvm_endorsements_b64) {
        fprintf(stderr, "Failed to load UVM endorsements\n");
        free(snp_report_b64);
        free(host_amd_certs_b64);
        return 1;
    }
    // Format the final output JSON
    printf(
        "{\n"
        "  \"evidence\": \"%s\",\n"
        "  \"endorsements\": \"%s\",\n"
        "  \"uvm_endorsements\": \"%s\"\n"
        "}",
        snp_report_b64,
        host_amd_certs_b64,
        uvm_endorsements_b64
    );

    // Clean up allocated resources
    free(snp_report_b64);
    free(host_amd_certs_b64);
    free(uvm_endorsements_b64);
    return 0;
}