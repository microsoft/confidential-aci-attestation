#!/usr/bin/env python
"""
Entry point module to mirror the C verify_attestation_ccf executable via -m.
"""
import sys
import argparse
import subprocess
from . import verify_attestation_ccf as _exe_verify

def main():
    # Parse command-line arguments matching the C executable interface
    parser = argparse.ArgumentParser(
        prog='verify_attestation_ccf',
        description='Verify SNP attestation from CCF attestation JSON.')
    parser.add_argument(
        '--report-data', dest='report_data', type=argparse.FileType('rb'), default=None,
        help='Optional report data file (opened as binary)')
    parser.add_argument(
        '--security-policy-b64', dest='security_policy_b64', required=True,
        help='Base64-encoded security policy')
    parser.add_argument(
        'ccf_attestation',
        help='CCF attestation JSON string')
    args = parser.parse_args()

    # Call the function
    with open(args.report_data.name, 'rb') as report_data_file:
        verify_succeeded = _exe_verify(
            ccf_attestation=args.ccf_attestation,
            report_data=report_data_file.read(),
            security_policy_b64=args.security_policy_b64
        )

    # Execute the C executable, streaming output to console
    sys.exit(0 if verify_succeeded else 1)

if __name__ == '__main__':
    main()