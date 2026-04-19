# Adapted from https://github.com/fugue/regula (FG_R00272).
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.fugue_tf_aws_iam_16

import rego.v1

import data.vulnetix.fugue.tf

metadata := {
	"id": "FUGUE-TF-AWS-IAM-16",
	"name": "IAM users should be members of at least one group",
	"description": "Permissions should be managed at the group level; users not assigned to any group may have permissions managed separately.",
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
	some u in tf.resources("aws_iam_user")
	not _user_in_group(u.name)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("IAM user %q is not a member of any aws_iam_group_membership.", [u.name]),
		"artifact_uri": u.path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": 1,
		"snippet": sprintf("%s.%s", [u.type, u.name]),
	}
}

_user_in_group(user_name) if {
	some gm in tf.resources("aws_iam_group_membership")
	tf.references(gm.block, "aws_iam_user", user_name)
}

_user_in_group(user_name) if {
	some gm in tf.resources("aws_iam_group_membership")
	some u in tf.string_list_attr(gm.block, "users")
	u == user_name
}

_user_in_group(user_name) if {
	some gum in tf.resources("aws_iam_user_group_membership")
	tf.references(gum.block, "aws_iam_user", user_name)
}
