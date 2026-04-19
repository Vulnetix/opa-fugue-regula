# opa-fugue-regula

Clean-room infrastructure-as-code security rules for the [Vulnetix CLI](https://github.com/Vulnetix/cli). Covers Terraform (AWS, Azure, GCP), AWS CloudFormation, Azure Resource Manager, and Kubernetes manifests — 275 rules mapped to CIS benchmarks, PCI-DSS, NIST 800-53, HIPAA, SOC2, and ISO 27001.

## Clean-Room Methodology

These rules were produced using a **clean-room** approach:

1. The security **intent** of each rule was derived from the [Fugue Regula](https://github.com/fugue/regula) project (Apache-2.0, Copyright 2020–2022 Fugue, Inc.) — specifically, the *what* and *why* of each misconfiguration check (e.g., "S3 buckets should enable server-side encryption").
2. The Rego **implementations** were independently written for the Vulnetix `input.file_contents` text-scanning schema. They do not incorporate code from Regula's Go-based HCL loader, parsed-resource graph, or `lib/` runtime.
3. The original Regula source served as a functional specification; the code here is a new expression of that specification.

This approach ensures the rules are purpose-built for Vulnetix while faithfully covering the same IaC misconfiguration surface that Regula addresses.

## What These Rules Cover

| Format | Cloud / Platform | Rules |
|--------|-----------------|-------|
| Terraform | AWS | 114 |
| Terraform | Azure | 38 |
| Terraform | GCP | 42 |
| CloudFormation | AWS | 23 |
| ARM Templates | Azure | 38 |
| Kubernetes | — | 20 |
| **Total** | | **275** |

Typical checks include:

- S3 bucket public access, encryption, logging, versioning
- IAM password / MFA / key rotation policies
- Security group overly-permissive ingress (0.0.0.0/0)
- RDS / Aurora encryption and backup settings
- EKS / AKS / GKE cluster hardening
- Azure storage account, SQL server, and Key Vault configuration
- GCP Compute, BigQuery, and IAM hardening
- CloudTrail / CloudWatch / Azure Monitor logging coverage
- Kubernetes pod security context, privileged containers, and RBAC

## Repository Structure

```
opa-fugue-regula/
├── rules/
│   ├── _lib/                    # shared helper packages (not rules)
│   │   ├── tf.rego              #   HCL regex-based extraction
│   │   ├── cfn.rego             #   CloudFormation YAML/JSON parsing
│   │   ├── arm.rego             #   ARM template JSON parsing
│   │   └── k8s.rego             #   Kubernetes YAML manifest parsing
│   ├── tf/
│   │   ├── aws/<service>/*.rego
│   │   ├── azurerm/<service>/*.rego
│   │   └── google/<service>/*.rego
│   ├── cfn/<service>/*.rego
│   ├── arm/<service>/*.rego
│   └── k8s/*.rego
├── LICENSE
└── README.md
```

## Usage

```bash
# Use alongside built-in rules
vulnetix scan --rule Vulnetix/opa-fugue-regula

# Use only these rules (disable built-ins)
vulnetix scan --rule Vulnetix/opa-fugue-regula --disable-default-rules

# Combine with other custom rule repos
vulnetix scan \
  --rule Vulnetix/opa-fugue-regula \
  --rule myorg/additional-rules
```

## Input Schema

Rules operate on Vulnetix's `input.file_contents` map (file path → raw file text). The `_lib` helper packages handle format-specific parsing:

- **Terraform**: regex-based HCL block extraction (no Go HCL parser required)
- **CloudFormation**: `yaml.unmarshal` / `json.unmarshal` on YAML/JSON templates
- **ARM**: `json.unmarshal` on ARM template JSON with schema detection
- **Kubernetes**: `yaml.unmarshal` with multi-document `---` splitting

## Rule Format

Each rule exports two values per the [Vulnetix custom rules spec](https://docs.vulnetix.io/docs/sast-rules/custom-rules/):

- `metadata` — rule identity, severity, CWE, tags
- `findings` — set of detected misconfiguration objects

## Attribution

The security check intent in this repository derives from [Fugue Regula](https://github.com/fugue/regula), Copyright 2020–2022 Fugue, Inc., licensed under the Apache License 2.0. The Rego implementations are original works written for the Vulnetix input schema.

## License

Apache License 2.0 — see [LICENSE](LICENSE).
