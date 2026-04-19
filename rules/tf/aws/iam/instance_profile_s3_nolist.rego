# Adapted from https://github.com/fugue/regula (FG_R00220).
# Ported to the Vulnetix Rego input schema (input.file_contents).
# Simplified: flags aws_iam_role_policy attached to roles referenced by aws_iam_instance_profile when the policy allows s3:List* / s3:ListAllMyBuckets / s3:*.

package vulnetix.rules.fugue_tf_aws_iam_03

import rego.v1

import data.vulnetix.fugue.tf

metadata := {
	"id": "FUGUE-TF-AWS-IAM-03",
	"name": "IAM roles attached to instance profiles should not allow broad list actions on S3",
	"description": "Trust policies attached to instance profiles should not allow list actions on S3 buckets to prevent compromised EC2 instances from enumerating buckets.",
	"help_uri": "https://github.com/fugue/regula",
	"languages": ["terraform", "hcl"],
	"severity": "medium",
	"level": "warning",
	"kind": "iac",
	"cwe": ["CWE-269"],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["terraform", "aws", "iam", "s3"],
}

findings contains finding if {
	some role in tf.resources("aws_iam_role")
	_is_in_instance_profile(role.name)
	some rp in tf.resources("aws_iam_role_policy")
	tf.references(rp.block, "aws_iam_role", role.name)
	_has_bad_s3_list(rp.block)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("IAM role %q (used as instance profile) has a policy allowing broad S3 list actions.", [role.name]),
		"artifact_uri": role.path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": 1,
		"snippet": sprintf("%s.%s", [role.type, role.name]),
	}
}

_is_in_instance_profile(role_name) if {
	some ip in tf.resources("aws_iam_instance_profile")
	tf.references(ip.block, "aws_iam_role", role_name)
}

_is_in_instance_profile(role_name) if {
	some ip in tf.resources("aws_iam_instance_profile")
	tf.string_attr(ip.block, "role") == role_name
}

_has_bad_s3_list(block) if {
	regex.match(`(?s)"Effect"\s*:\s*"Allow"[\s\S]*?"Action"\s*:\s*"(?:s3:ListAllMyBuckets|s3:\*|s3:List\*)"`, block)
}

_has_bad_s3_list(block) if {
	regex.match(`"Action"\s*:\s*\[[^\]]*"(?:s3:ListAllMyBuckets|s3:\*|s3:List\*)"`, block)
}
