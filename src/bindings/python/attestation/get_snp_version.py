#!/usr/bin/env python
"""
Entry point module to mirror the C get_snp_version executable via -m.
"""
import sys
from . import get_snp_version as _get_version

def main():
    version = _get_version()
    sys.stdout.write(version)
    sys.exit(0)

if __name__ == '__main__':
    main()