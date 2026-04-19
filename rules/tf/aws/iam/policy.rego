# Adapted from https://github.com/fugue/regula (FG_R00007).
# Ported to the Vulnetix Rego input schema (input.file_contents).
# Flags aws_iam_user_policy (inline) and aws_iam_user_policy_attachment as best-effort signal of policies attached directly to users.

package vulnetix.rules.fugue_tf_aws_iam_13

import rego.v1

import data.vulnetix.fugue.tf

metadata := {
	"id": "FUGUE-TF-AWS-IAM-13",
	"name": "IAM policies should not be attached to users",
	"description": "Assigning privileges at the group or role level reduces the complexity of access management. Reducing complexity may reduce opportunity for a principal to inadvertently receive excessive privileges.",
	"help_uri": "https://github.com/fugue/regula",
	"languages": ["terraform", "hcl"],
	"severity": "low",
	"level": "note",
	"kind": "iac",
	"cwe": ["CWE-269"],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["terraform", "aws", "iam"],
}

findings contains finding if {
	some ty in {"aws_iam_user_policy", "aws_iam_user_policy_attachment"}
	some r in tf.resources(ty)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("%s.%s attaches a policy directly to a user; prefer groups/roles.", [r.type, r.name]),
		"artifact_uri": r.path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": 1,
		"snippet": sprintf("%s.%s", [r.type, r.name]),
	}
}
