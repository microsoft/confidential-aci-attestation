import json
from attestation import get_snp_version, get_attestation_ccf, verify_attestation_ccf
import os
from base64 import b64encode


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
