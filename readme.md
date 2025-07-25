# Confidential-ACI-Attestation [![CI](https://github.com/microsoft/confidential-aci-attestation/actions/workflows/ci.yml/badge.svg)](https://github.com/microsoft/confidential-aci-attestation/actions/workflows/ci.yml) 

## Overview

This is a C library for getting and verifying attestations from Confidential ACI. It is written in C for maximum portability and has language specific bindings. Current ways to use this library are:

- Standalone C executables
- Docker image
- Python package

## Installation

If running from source, run:

```
make
```

To build the C executables, you can then build the targets depending on your preferred method of running:

```
make python
```

```
make docker
```

## Usage

### C executables

The C executables live under build/ to run, simply execute the binary.

```
./build/get_snp_version
./build/get_attestation_ccf
```

The `get_attestation_*` binaries will fetch genuine attestation reports if running on genuine SEV-SNP machines, otherwise they will return attestations based on the files under [examples](examples/).

These sample values were captured on an C-ACI instance running a version of the container defined in [compose.yml](compose.yml) with the [allow_all.rego](examples/security_policies/allow_all.rego) security policy.

You can also run the verification code against a generated report, just ensure the format of the attestation (which follows the `get_attestation_` part of the binary name) matches between `get_` and `verify_`. For example:

```
attestation=$(./build/get_attestation_ccf "example-report-data")

./build/verify_attestation_ccf \
    --report-data "example-report-data" \
    --security-policy-b64 "$(cat examples/security_policies/allow_all.rego | base64 -w 0)" \
    "$attestation"
```

### Python package

```
attestation=$(python -m attestation.get_attestation_ccf "example-report-data")

python -m attestation.verify_attestation_ccf \
    --report-data "example-report-data" \
    --security-policy-b64 "$(cat examples/security_policies/allow_all.rego | base64 -w 0)" \
    "$attestation"
```

### Docker image

```
image="ghcr.io/microsoft/confidential-aci-attestation:latest"

attestation=$(docker run $image get_attestation_ccf "example-report-data")

docker run $image verify_attestation_ccf \
    --report-data "example-report-data" \
    --security-policy-b64 "$(cat examples/security_policies/allow_all.rego | base64 -w 0)" \
    "$attestation"
```

## Contributing

When making changes, you can verify them with:

```
make lint
make test
```

This will lint the C code, and run unit tests, test the roundtrip of getting a virtual attestation and verifying it (similar to the example above).

You can also run this roundtrip test in real C-ACI, with:

```
make test-aci
```

This will take slightly longer than the other tests, which is why it isn't run implicitly.

This project has adopted the [Microsoft Open Source Code of Conduct](https://opensource.microsoft.com/codeofconduct/).
For more information see the [Code of Conduct FAQ](https://opensource.microsoft.com/codeofconduct/faq/) or
contact [opencode@microsoft.com](mailto:opencode@microsoft.com) with any additional questions or comments.
