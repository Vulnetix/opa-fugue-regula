# Adapted from https://github.com/fugue/regula (FG_R00219).
# Ported to the Vulnetix Rego input schema (input.file_contents).
# Simplified: text-scans assume_role_policy for Principal:* with sts:AssumeRole.

package vulnetix.rules.fugue_tf_aws_iam_02

import rego.v1

import data.vulnetix.fugue.tf

metadata := {
	"id": "FUGUE-TF-AWS-IAM-02",
	"name": "IAM role trust policies should not allow all principals",
	"description": "Using a wildcard in the Principal element of a role's trust policy allows any IAM user in any account to assume the role, exposing sensitive data.",
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
	"tags": ["terraform", "aws", "iam", "wildcard"],
}

findings contains finding if {
	some r in tf.resources("aws_iam_role")
	_has_wildcard_trust(r.block)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("IAM role %q has an assume_role_policy with Principal:* and sts:AssumeRole.", [r.name]),
		"artifact_uri": r.path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": 1,
		"snippet": sprintf("%s.%s", [r.type, r.name]),
	}
}

_has_wildcard_trust(block) if {
	regex.match(`(?s)"Effect"\s*:\s*"Allow"[\s\S]*?"Principal"\s*:\s*"\*"[\s\S]*?"Action"\s*:\s*"(?:\*|sts:AssumeRole)"`, block)
}

_has_wildcard_trust(block) if {
	regex.match(`(?s)"Effect"\s*:\s*"Allow"[\s\S]*?"Principal"\s*:\s*\{\s*"AWS"\s*:\s*"\*"\s*\}[\s\S]*?"Action"\s*:\s*"(?:\*|sts:AssumeRole)"`, block)
}
