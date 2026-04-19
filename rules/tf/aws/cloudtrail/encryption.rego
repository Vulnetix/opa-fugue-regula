# Adapted from https://github.com/fugue/regula (FG_R00035).
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.fugue_tf_aws_ct_02

import rego.v1

import data.vulnetix.fugue.tf

metadata := {
	"id": "FUGUE-TF-AWS-CT-02",
	"name": "CloudTrail log files should be encrypted with customer managed KMS keys",
	"description": "To get control over key rotation and obtain auditing visibility into key usage, use SSE-KMS to encrypt CloudTrail log files with customer managed KMS keys.",
	"help_uri": "https://github.com/fugue/regula",
	"languages": ["terraform", "hcl"],
	"severity": "high",
	"level": "error",
	"kind": "iac",
	"cwe": ["CWE-311"],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["terraform", "aws", "cloudtrail", "encryption"],
}

findings contains finding if {
	some r in tf.resources("aws_cloudtrail")
	not tf.has_key(r.block, "kms_key_id")
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("CloudTrail %q does not set kms_key_id for SSE-KMS encryption.", [r.name]),
		"artifact_uri": r.path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": 1,
		"snippet": sprintf("%s.%s", [r.type, r.name]),
	}
}
