# Adapted from https://github.com/fugue/regula (FG_R00068).
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.fugue_tf_aws_cw_02

import rego.v1

import data.vulnetix.fugue.tf

metadata := {
	"id": "FUGUE-TF-AWS-CW-02",
	"name": "CloudWatch log groups should be encrypted with customer managed KMS keys",
	"description": "CloudWatch log groups should be encrypted with customer managed KMS keys to give users control over key rotation and auditing visibility.",
	"help_uri": "https://github.com/fugue/regula",
	"languages": ["terraform", "hcl"],
	"severity": "medium",
	"level": "warning",
	"kind": "iac",
	"cwe": ["CWE-311"],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["terraform", "aws", "cloudwatch", "encryption"],
}

findings contains finding if {
	some r in tf.resources("aws_cloudwatch_log_group")
	not tf.has_key(r.block, "kms_key_id")
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("CloudWatch log group %q has no kms_key_id.", [r.name]),
		"artifact_uri": r.path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": 1,
		"snippet": sprintf("%s.%s", [r.type, r.name]),
	}
}
