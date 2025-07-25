#ifndef EMBEDDED_EXAMPLES_H
#define EMBEDDED_EXAMPLES_H

// Symbols defined by embedded_examples.S via .incbin
extern const unsigned char snp_report_b64_start[];
extern const unsigned char snp_report_b64_end[];

extern const unsigned char host_amd_certs_b64_start[];
extern const unsigned char host_amd_certs_b64_end[];

// Symbols for UVM endorsements example file (base64)
extern const unsigned char reference_info_b64_start[];
extern const unsigned char reference_info_b64_end[];

#endif // EMBEDDED_EXAMPLES_H