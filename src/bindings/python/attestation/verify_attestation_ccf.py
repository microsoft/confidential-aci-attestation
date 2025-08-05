#!/usr/bin/env python
"""
Entry point module to mirror the C verify_attestation_ccf executable via -m.
"""
import sys
import argparse
import subprocess
from . import _exe_verify

def main():
    # Parse command-line arguments matching the C executable interface
    parser = argparse.ArgumentParser(
        prog='verify_attestation_ccf',
        description='Verify SNP attestation from CCF attestation JSON.')
    parser.add_argument(
        '--report-data', dest='report_data', default='',
        help='Optional report data string')
    parser.add_argument(
        '--security-policy-b64', dest='security_policy_b64', required=True,
        help='Base64-encoded security policy')
    parser.add_argument(
        'ccf_attestation',
        help='CCF attestation JSON string')
    args = parser.parse_args()
    # Build subprocess arguments for the C executable
    cmd = [_exe_verify]
    if args.report_data:
        cmd.extend(['--report-data', args.report_data])
    cmd.extend(['--security-policy-b64', args.security_policy_b64])
    cmd.append(args.ccf_attestation)
    # Execute the C executable, streaming output to console
    result = subprocess.run(cmd)
    sys.exit(result.returncode)

if __name__ == '__main__':
    main()