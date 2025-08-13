#!/usr/bin/env python
"""
Entry point module to mirror the C get_attestation_ccf executable via -m.
"""
import sys
import subprocess
from . import get_attestation_ccf as _get_att

def main():
    args = sys.argv[1:]
    try:
        report_data = b''
        if args:
            with open(args[0], "rb") as report_data_file:
                report_data = report_data_file.read()
        output = _get_att(report_data)
        sys.stdout.write(output)
        sys.exit(0)
    except subprocess.CalledProcessError as e:
        sys.exit(e.returncode)

if __name__ == '__main__':
    main()