 #include "verification.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <openssl/evp.h>
#include <openssl/ecdsa.h>
#include <openssl/obj_mac.h>
#include <openssl/x509.h>
#include "base64.h"
#include "sha256.h"
#include "hex.h"
#include "json.h"
#include <unistd.h>

const char* amd_public_key_pem =
    "-----BEGIN PUBLIC KEY-----\n"
    "MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEA0Ld52RJOdeiJlqK2JdsV\n"
    "mD7FktuotWwX1fNgW41XY9Xz1HEhSUmhLz9Cu9DHRlvgJSNxbeYYsnJfvyjx1MfU\n"
    "0V5tkKiU1EesNFta1kTA0szNisdYc9isqk7mXT5+KfGRbfc4V/9zRIcE8jlHN61S\n"
    "1ju8X93+6dxDUrG2SzxqJ4BhqyYmUDruPXJSX4vUc01P7j98MpqOS95rORdGHeI5\n"
    "2Naz5m2B+O+vjsC060d37jY9LFeuOP4Meri8qgfi2S5kKqg/aF6aPtuAZQVR7u3K\n"
    "FYXP59XmJgtcog05gmI0T/OitLhuzVvpZcLph0odh/1IPXqx3+MnjD97A7fXpqGd\n"
    "/y8KxX7jksTEzAOgbKAeam3lm+3yKIcTYMlsRMXPcjNbIvmsBykD//xSniusuHBk\n"
    "gnlENEWx1UcbQQrs+gVDkuVPhsnzIRNgYvM48Y+7LGiJYnrmE8xcrexekBxrva2V\n"
    "9TJQqnN3Q53kt5viQi3+gCfmkwC0F0tirIZbLkXPrPwzZ0M9eNxhIySb2npJfgnq\n"
    "z55I0u33wh4r0ZNQeTGfw03MBUtyuzGesGkcw+loqMaq1qR4tjGbPYxCvpCq7+Og\n"
    "pCCoMNit2uLo9M18fHz10lOMT8nWAUvRZFzteXCm+7PHdYPlmQwUw3LvenJ/ILXo\n"
    "QPHfbkH0CyPfhl1jWhJFZasCAwEAAQ==\n"
    "-----END PUBLIC KEY-----\n";


const char* aci_uvm_feed = "ContainerPlat-AMD-UVM";
const char* aci_uvm_iss = "did:x509:0:sha256:I__iuL25oXEVFdTP_aBLx_eT1RPHbCQ_ECBQfYZpt9s::eku:1.3.6.1.4.1.311.76.59.1.2";
const int aci_uvm_min_svn = 100;


int verify_snp_report_is_genuine(SnpReport* snp_report, cert_chain_t* cert_chain) {
    fprintf(stderr, "\n----------------------------------------------------\n");
    fprintf(stderr, "\nVerifying SNP report is signed by a chain of certs going to AMD's root of trust\n");
    fprintf(stderr, "\nAMD's public key:\n%s\n", amd_public_key_pem);

    if (cert_chain_validate(cert_chain, 3) == 0) {
        fprintf(stderr, "✔ Certificates signature chain valid\n");
    } else {
        fprintf(stderr, "✘ Certificates signature chain invalid\n");
        return 1;
    }

    EVP_PKEY* amd_public_key = pem_to_pub_key(amd_public_key_pem);
    if (cert_chain_validate_root(cert_chain, amd_public_key) == 0) {
        fprintf(stderr, "✔ AMD's public key is the root of the chain\n");
    } else {
        fprintf(stderr, "✘ AMD's public key isn't the root of the chain\n");
        return 1;
    }
    pub_key_free(amd_public_key);

    uint8_t* snp_report_without_signature = remove_signature(snp_report);
    if (cert_chain_validate_signature(cert_chain, &snp_report->signature, snp_report_without_signature)) {
        fprintf(stderr, "✔ SNP report is signed by certificate chain\n");
    } else {
        fprintf(stderr, "✘ SNP report isn't signed by the certificate chain\n");
        return 1;
    }
    free(snp_report_without_signature);

    return 0;
}


int verify_snp_report_has_report_data(SnpReport* snp_report, snp_report_data_t* report_data) {
    fprintf(stderr, "\n----------------------------------------------------\n");
    fprintf(stderr, "\nVerifying SNP report has the expected report data\n");

    char* actual = format_report_data(snp_report->report_data,
                                      sizeof(snp_report->report_data));
    fprintf(stderr, "\nActual: \n%s\n", actual ? actual : "(format error)");
    free(actual);

    char* expect = format_report_data(*report_data,
                                     sizeof(*report_data));
    fprintf(stderr, "\nExpected: \n%s\n", expect ? expect : "(format error)");
    free(expect);

    if (memcmp(snp_report->report_data, report_data, sizeof(snp_report_data_t)) == 0) {
        fprintf(stderr, "\n✔ Report data matches\n");
        return 0;
    } else {
        fprintf(stderr, "\n✘ Report data does not match\n");
        return 1;
    }
}


int verify_snp_report_has_security_policy(SnpReport* snp_report, const char* security_policy_b64) {
    fprintf(stderr, "\n----------------------------------------------------\n");
    fprintf(stderr, "\nVerifying SNP report's host_data field matches the expected security policy\n");

    size_t policy_len = 0;
    uint8_t* security_policy = base64_decode(security_policy_b64, strlen(security_policy_b64), &policy_len);
    if (!security_policy) {
        fprintf(stderr, "Failed to decode security policy\n");
        return 1;
    }

    fprintf(stderr, "\nExpected Security Policy: \n```\n");
    fwrite(security_policy, 1, policy_len, stderr);
    fprintf(stderr, "```\n");

    uint8_t* policy_hash = sha256(security_policy, policy_len);
    free(security_policy);
    if (!policy_hash) {
        fprintf(stderr, "Failed to compute SHA-256 hash of security policy\n");
        return 1;
    }

    // Print policy hash and report host_data in hex, then free buffers
    char* policy_hex = hex_encode(policy_hash, sizeof(snp_report->host_data), 16, NULL);
    if (policy_hex) {
        fprintf(stderr, "\nSecurity Policy SHA256: \n%s\n", policy_hex);
        free(policy_hex);
    }
    char* host_data_hex = hex_encode(snp_report->host_data, sizeof(snp_report->host_data), 16, NULL);
    if (host_data_hex) {
        fprintf(stderr, "\nSNP Report Host Data: \n%s\n", host_data_hex);
        free(host_data_hex);
    }

    if (memcmp(policy_hash, snp_report->host_data, sizeof(snp_report->host_data)) == 0) {
        fprintf(stderr, "\n✔ SNP report's host_data matches the security policy hash\n");
        free(policy_hash);
        return 0;
    } else {
        fprintf(stderr, "\n✘ SNP report's host_data does not match security policy hash\n");
        free(policy_hash);
        return 1;
    }
}

int verify_utility_vm_build(SnpReport* snp_report, COSE_Sign1* uvm_endorsement) {
    fprintf(stderr, "\n----------------------------------------------------\n");
    fprintf(stderr, "\nVerifying Utility VM in SNP Report is endorsed by Microsoft\n");

    // Check if COSE_Sign1 document is signed by Microsoft
    fprintf(stderr, "\nEndorsement Issuer: \n%s", uvm_endorsement->protected_header->iss);
    if (strcmp(uvm_endorsement->protected_header->iss, aci_uvm_iss) != 0) {
        fprintf(stderr, "\n✘ Endorsement issuer does not match expected value\n");
        return 1;
    }
    fprintf(stderr, " ✔\n");

    fprintf(stderr, "\nEndorsement Feed: \n%s", uvm_endorsement->protected_header->feed);
    if (strcmp(uvm_endorsement->protected_header->feed, aci_uvm_feed) != 0) {
        fprintf(stderr, "\n✘ Endorsement feed does not match expected value\n");
        return 1;
    }
    fprintf(stderr, " ✔\n");

    char* svn = get_json_field((char*)uvm_endorsement->payload, "x-ms-sevsnpvm-guestsvn");
    fprintf(stderr, "\nEndorsement SVN: \n%d (min: %d)", atoi(svn), aci_uvm_min_svn);
    if (atoi(svn) < aci_uvm_min_svn) {
        fprintf(stderr, "\n✘ Endorsement SVN does not meet minimum SVN\n");
        return 1;
    }
    fprintf(stderr, " ✔\n");
    free(svn);

    if (cert_chain_validate(uvm_endorsement->protected_header->x5_chain, 3) != 0) {
        fprintf(stderr, "\n✘ Endorsement certificate chain is invalid\n");
        return 1;
    }

    if (verify_cose_sign1_signature(uvm_endorsement)) {
        fprintf(stderr, "\n✘ COSE_Sign1 signature verification failed\n");
        return 1;
    }

    fprintf(stderr, "\n✔ COSE signature verified\n");

    // Get the reported launch measurement
    char* reported_hex = hex_encode(snp_report->measurement, sizeof(snp_report->measurement), 16, NULL);
    if (reported_hex) {
        fprintf(stderr, "\nSNP Report Launch Measurement: \n%s\n", reported_hex);
        free(reported_hex);
    }

    // Get the endorsed launch measurement
    char* launch_measurement_hex_str = get_json_field((char*)uvm_endorsement->payload, "x-ms-sevsnpvm-launchmeasurement");
    if (!launch_measurement_hex_str) {
        fprintf(stderr, "✘ Failed to extract launch measurement from COSE_Sign1 payload\n");
        return 1;
    }
    uint8_t* launch_measurement = hex_decode(
        launch_measurement_hex_str,
        strlen(launch_measurement_hex_str),
        NULL
    );
    // Print endorsed launch measurement and clean up
    char* endorsed_hex = hex_encode(launch_measurement, sizeof(snp_report->measurement), 16, NULL);
    if (endorsed_hex) {
        fprintf(stderr, "\nEndorsed Launch Measurement: \n%s\n", endorsed_hex);
        free(endorsed_hex);
    }
    free(launch_measurement_hex_str);

    // Check the endorsed and reported launch measurements are the same
    if (memcmp(launch_measurement, snp_report->measurement, sizeof(snp_report->measurement)) == 0) {
        fprintf(stderr, "\n✔ Utility VM endorsement matches SNP report\n");
        free(launch_measurement);
        return 0;
    } else {
        fprintf(stderr, "\n✘ Utility VM endorsement does not match SNP report\n");
        free(launch_measurement);
        return 1;
    }
}