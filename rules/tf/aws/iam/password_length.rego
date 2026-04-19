# Adapted from https://github.com/fugue/regula (FG_R00025).
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.fugue_tf_aws_iam_05

import rego.v1

import data.vulnetix.fugue.tf

metadata := {
	"id": "FUGUE-TF-AWS-IAM-05",
	"name": "IAM password policies should require a minimum length of 14",
	"description": "Setting a password complexity policy increases account resiliency against brute force login attempts.",
	"help_uri": "https://github.com/fugue/regula",
	"languages": ["terraform", "hcl"],
	"severity": "medium",
	"level": "warning",
	"kind": "iac",
	"cwe": ["CWE-521"],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["terraform", "aws", "iam", "password"],
}

findings contains finding if {
	some r in tf.resources("aws_iam_account_password_policy")
	not _valid(r.block)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("IAM password policy %q has minimum_password_length < 14 or missing.", [r.name]),
		"artifact_uri": r.path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": 1,
		"snippet": sprintf("%s.%s", [r.type, r.name]),
	}
}

_valid(block) if {
	n := tf.number_attr(block, "minimum_password_length")
	n >= 14
}
