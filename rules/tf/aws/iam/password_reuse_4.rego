# Adapted from https://github.com/fugue/regula (FG_R00088).
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.fugue_tf_aws_iam_09

import rego.v1

import data.vulnetix.fugue.tf

metadata := {
	"id": "FUGUE-TF-AWS-IAM-09",
	"name": "IAM password policies should prevent reuse of the four previously used passwords",
	"description": "Password policies should prevent users from reusing any of their previous 4 passwords.",
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
		"message": sprintf("IAM password policy %q has password_reuse_prevention < 4 or missing.", [r.name]),
		"artifact_uri": r.path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": 1,
		"snippet": sprintf("%s.%s", [r.type, r.name]),
	}
}

_valid(block) if {
	n := tf.number_attr(block, "password_reuse_prevention")
	n >= 4
}
