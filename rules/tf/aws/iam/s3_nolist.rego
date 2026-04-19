# Adapted from https://github.com/fugue/regula (FG_R00218).
# Ported to the Vulnetix Rego input schema (input.file_contents).
# Simplified: text-scans inline policy bodies for broad s3:List* actions.

package vulnetix.rules.fugue_tf_aws_iam_14

import rego.v1

import data.vulnetix.fugue.tf

metadata := {
	"id": "FUGUE-TF-AWS-IAM-14",
	"name": "IAM policies should not allow broad list actions on S3 buckets",
	"description": "IAM policies with broad list actions such as s3:ListAllMyBuckets enable adversaries to enumerate buckets and extract sensitive data.",
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

policy_types := {"aws_iam_policy", "aws_iam_group_policy", "aws_iam_role_policy", "aws_iam_user_policy"}

findings contains finding if {
	some ty in policy_types
	some r in tf.resources(ty)
	_has_bad_list(r.block)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("IAM policy %q (%s) allows broad s3 list actions on wildcard resource.", [r.name, r.type]),
		"artifact_uri": r.path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": 1,
		"snippet": sprintf("%s.%s", [r.type, r.name]),
	}
}

_has_bad_list(block) if {
	regex.match(`(?s)"Effect"\s*:\s*"Allow"[\s\S]*?"Action"\s*:\s*"(?:s3:ListAllMyBuckets|s3:\*|s3:List\*)"[\s\S]*?"Resource"\s*:\s*"\*"`, block)
}

_has_bad_list(block) if {
	regex.match(`(?s)"Effect"\s*:\s*"Allow"[\s\S]*?"Action"\s*:\s*\[[^\]]*"(?:s3:ListAllMyBuckets|s3:\*|s3:List\*)"[^\]]*\][\s\S]*?"Resource"\s*:\s*"\*"`, block)
}
