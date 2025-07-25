// verification.h
// Prototypes for SNP report verification routines
#ifndef VERIFICATION_H
#define VERIFICATION_H

#include "snp_report.h"
#include "cert_chain.h"
#include "cose.h"

#ifdef __cplusplus
extern "C" {
#endif

// Verify that the SNP report is genuine using the provided certificate chain
// Returns 0 on success, non-zero on failure.
int verify_snp_report_is_genuine(SnpReport* snp_report, cert_chain_t* cert_chain);

// Verify that the SNP report contains the expected report_data
// Returns 0 on success, non-zero on failure.
int verify_snp_report_has_report_data(SnpReport* snp_report, snp_report_data_t* report_data);

// Verify that the SNP report's host_data matches the provided security policy (base64 encoded)
// Returns 0 on success, non-zero on failure.
int verify_snp_report_has_security_policy(SnpReport* snp_report, const char* security_policy_b64);

/*
 * Verify a COSE_Sign1 document (endorsement of UVM) in-memory buffer.
 * buf/len is the COSE_Sign1 message; trust anchor and expected claims
 * are set in the implementation.
 * Returns 0 on success, non-zero on failure.
 */
int verify_utility_vm_build(SnpReport* snp_report, COSE_Sign1* uvm_endorsement);

#ifdef __cplusplus
}
#endif

#endif // VERIFICATION_H