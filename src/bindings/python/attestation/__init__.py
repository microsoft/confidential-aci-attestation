"""
attestation
-----------

Python bindings for the SNP attestation C core.
Provides high-level functions wrapping the C executables.
"""
# Standard imports
import os
import shutil
import subprocess

# Locate executables with fallback for editable installs
_pkg_dir = os.path.dirname(__file__)
def _locate_exec(name: str) -> str:
    # 1) bundled next to this __init__.py
    candidate = os.path.join(_pkg_dir, name)
    if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
        return candidate
    # 2) on PATH
    path = shutil.which(name)
    if path:
        return path
    # 3) in project build/ directory relative to this module (dev mode)
    p = _pkg_dir
    while True:
        build_path = os.path.join(p, 'build', name)
        if os.path.isfile(build_path) and os.access(build_path, os.X_OK):
            return build_path
        parent = os.path.dirname(p)
        if parent == p:
            break
        p = parent
    raise FileNotFoundError(
        f"Executable '{name}' not found in {candidate}, PATH, or project build directory"
    )

_exe_get_att = _locate_exec('get_attestation_ccf')
_exe_verify = _locate_exec('verify_attestation_ccf')
_exe_snp_version = _locate_exec('get_snp_version')

__all__ = [
    'get_attestation_ccf',
    'verify_attestation_ccf',
    'get_snp_version',
]

def get_attestation_ccf(report_data: str = '') -> str:
    """
    Retrieve a SNP attestation JSON string.

    :param report_data: Optional report_data string (max 64 bytes).
    :returns: JSON string with evidence and endorsements.
    """
    args = [_exe_get_att]
    if report_data:
        args.append(report_data)
    result = subprocess.run(args, capture_output=True, text=True, check=True)
    return result.stdout

def verify_attestation_ccf(ccf_attestation: str, report_data: str = '', security_policy_b64: str = '') -> bool:
    """
    Verify a SNP attestation JSON string.

    :param ccf_attestation: JSON string produced by get_attestation.
    :param report_data: Optional report_data string used in attestation.
    :param security_policy_b64: Base64-encoded security policy.
    :returns: True if verification succeeds, False otherwise.
    """
    args = [_exe_verify]
    args.append(ccf_attestation)
    if report_data:
        args.extend(['--report-data', report_data])
    if security_policy_b64:
        args.extend(['--security-policy-b64', security_policy_b64])

    result = subprocess.run(args)
    return result.returncode == 0

def get_snp_version() -> str:
    """
    Query the SNP version of the current environment.

    :returns: Version string, e.g., "SNP Version: Virtual".
    """
    result = subprocess.run([_exe_snp_version], capture_output=True, text=True, check=True)
    return result.stdout.strip()