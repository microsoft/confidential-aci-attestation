/*
 * Embed example files into read-only data via assembler. This allows the binary
 * to access the files in examples/
 */
.section .rodata

    .global snp_report_b64_start
snp_report_b64_start:
    .incbin "examples/snp-report-base64"
    .global snp_report_b64_end
snp_report_b64_end:

.global host_amd_certs_b64_start
host_amd_certs_b64_start:
    .incbin "examples/host-amd-certs-base64"
.global host_amd_certs_b64_end
host_amd_certs_b64_end:
// Embed UVM reference endorsements for virtual mode
.global reference_info_b64_start
reference_info_b64_start:
    .incbin "examples/reference-info-base64"
.global reference_info_b64_end
reference_info_b64_end: