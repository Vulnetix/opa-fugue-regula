# Adapted from https://github.com/fugue/regula (FG_R00092).
# Ported to the Vulnetix Rego input schema (input.file_contents).
# Simplified: text-scans inline policy bodies for Allow/Action:*/Resource:* patterns.

package vulnetix.rules.fugue_tf_aws_iam_01

import rego.v1

import data.vulnetix.fugue.tf

metadata := {
	"id": "FUGUE-TF-AWS-IAM-01",
	"name": "IAM policies should not have full \"*:*\" administrative privileges",
	"description": "IAM policies should start with a minimum set of permissions. Providing full administrative privileges exposes resources to potentially unwanted actions.",
	"help_uri": "https://github.com/fugue/regula",
	"languages": ["terraform", "hcl"],
	"severity": "high",
	"level": "error",
	"kind": "iac",
	"cwe": ["CWE-269"],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["terraform", "aws", "iam", "wildcard"],
}

policy_types := {"aws_iam_policy", "aws_iam_group_policy", "aws_iam_role_policy", "aws_iam_user_policy"}

findings contains finding if {
	some ty in policy_types
	some r in tf.resources(ty)
	tf.has_wildcard_allow_star(r.block)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("IAM policy %q (%s) contains an Allow statement with Action:* and Resource:*.", [r.name, r.type]),
		"artifact_uri": r.path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": 1,
		"snippet": sprintf("%s.%s", [r.type, r.name]),
	}
}
