import json
import os
from base64 import b64encode
import subprocess
import sys
from itertools import chain


def execute_module(module_name, *args, **kwargs):
    return subprocess.run(
        [
            sys.executable,
            '-m',
            f'attestation.{module_name}',
            *args,
            *(list(chain.from_iterable(zip([f'--{k.replace('_', "-")}' for k in kwargs.keys()], list(kwargs.values())))) if kwargs else []),
        ],
        stdout=subprocess.PIPE,
        text=True
    )


def get_snp_version():
    return execute_module('get_snp_version').stdout.strip()


def get_attestation_ccf(report_data: str = '') -> str:
    return execute_module('get_attestation_ccf', report_data).stdout.strip()


def verify_attestation_ccf(ccf_attestation: str, report_data: str = '', security_policy_b64: str = '') -> bool:
    return execute_module(
        'verify_attestation_ccf',
        ccf_attestation,
        report_data=report_data,
        security_policy_b64=security_policy_b64,
    ).returncode == 0


def get_security_policy_b64():
    policy_path = os.path.abspath(
        os.path.join(os.getcwd(), 'examples', 'security_policies', 'allow_all.rego')
    )
    with open(policy_path, 'rb') as f:
        return b64encode(f.read()).decode('utf-8')


def test_get_snp_version():
    if os.path.exists("/dev/sev-guest"):
        assert "SNP Version: 6" in get_snp_version()
    elif os.path.exists("/dev/sev"):
        assert "SNP Version: 5" in get_snp_version()
    else:
        assert "SNP Version: Virtual" in get_snp_version()


def test_get_attestation_ccf():
    ccf_attestation = json.loads(get_attestation_ccf())
    assert "evidence" in ccf_attestation
    assert "endorsements" in ccf_attestation
    assert "uvm_endorsements" in ccf_attestation


def test_get_attestation_ccf_with_report_data():
    ccf_attestation = json.loads(get_attestation_ccf("hello"))
    assert "evidence" in ccf_attestation
    assert "endorsements" in ccf_attestation
    assert "uvm_endorsements" in ccf_attestation


def test_verify_attestation_ccf():
    ccf_attestation = get_attestation_ccf()
    assert verify_attestation_ccf(
        ccf_attestation,
        report_data="example-report-data",
        security_policy_b64=get_security_policy_b64()
    ) == True


def test_verify_attestation_ccf_bad_report_data():
    ccf_attestation = get_attestation_ccf()
    assert verify_attestation_ccf(
        ccf_attestation,
        report_data="bad-report-data",
        security_policy_b64=get_security_policy_b64()
    ) == False


def test_verify_attestation_ccf_bad_security_policy():
    ccf_attestation = get_attestation_ccf()
    assert verify_attestation_ccf(
        ccf_attestation,
        report_data="example-report-data",
        security_policy_b64=b64encode(b"bad-policy").decode('utf-8')
    ) == False
