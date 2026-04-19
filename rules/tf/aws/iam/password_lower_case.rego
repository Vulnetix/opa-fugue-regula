# Adapted from https://github.com/fugue/regula (FG_R00022).
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.fugue_tf_aws_iam_06

import rego.v1

import data.vulnetix.fugue.tf

metadata := {
	"id": "FUGUE-TF-AWS-IAM-06",
	"name": "IAM password policies should require at least one lowercase character",
	"description": "IAM password policies are used to enforce password complexity requirements.",
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
	tf.is_not_true(r.block, "require_lowercase_characters")
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("IAM password policy %q does not require lowercase characters.", [r.name]),
		"artifact_uri": r.path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": 1,
		"snippet": sprintf("%s.%s", [r.type, r.name]),
	}
}
