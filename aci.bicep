param location string = resourceGroup().location
param ccePolicies object

resource attestation 'Microsoft.ContainerInstance/containerGroups@2023-05-01' = {
  name: deployment().name
  location: location
  properties: {
    osType: 'Linux'
    sku: 'Confidential'
    restartPolicy: 'Never'
    confidentialComputeProperties: {
      ccePolicy: ccePolicies.aci
    }
    containers: [
      {
        name: 'attestation'
        properties: {
          image: 'ghcr.io/microsoft/confidential-aci-attestation:latest'
          resources: {
            requests: {
              memoryInGB: 2
              cpu: 1
            }
          }
          command: [
            '/bin/bash'
            '-c'
            join(
              [
                'get_snp_version &&'
                'echo "$(get_attestation_ccf)" &&'
                'get_attestation_ccf "example-report-data" | xargs -0'
                'verify_attestation_ccf'
                '--report-data "example-report-data"'
                '--security-policy-b64 "$(cat /src/policy_aci.rego | base64 -w 0)" &&'
                'until curl -sf http://127.0.0.1:5000/get_snp_version >/dev/null; do sleep 1; done &&'
                'curl http://127.0.0.1:5000/get_attestation_ccf?report_data=example-report-data | xargs -0'
                'verify_attestation_ccf'
                '--report-data "example-report-data"'
                '--security-policy-b64 "$(cat /src/policy_aci.rego | base64 -w 0)" &&'
                'echo "All tests passed"'
              ],
              ' '
            )
          ]
        }
      }
      {
        name: 'attestation-server'
        properties: {
          image: 'ghcr.io/microsoft/confidential-aci-attestation:latest'
          ports: [
            {
              port: 5000
              protocol: 'TCP'
            }
          ]
          resources: {
            requests: {
              memoryInGB: 2
              cpu: 1
            }
          }
          command: ['server']
        }
      }
    ]
  }
}

output ids array = [
  attestation.id
]
