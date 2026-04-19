# Adapted from https://github.com/fugue/regula (FG_R00252).
# Ported to the Vulnetix Rego input schema (input.file_contents).
# Simplified: text-scan inline key policy for Allow with AWS:"*" principal and no caller condition.

package vulnetix.rules.fugue_tf_aws_kms_01

import rego.v1

import data.vulnetix.fugue.tf

metadata := {
	"id": "FUGUE-TF-AWS-KMS-01",
	"name": "KMS master keys should not be publicly accessible",
	"description": "KMS master keys should not be publicly accessible. Publicly accessible KMS keys may allow anyone to perform decryption operations which may reveal sensitive data.",
	"help_uri": "https://github.com/fugue/regula",
	"languages": ["terraform", "hcl"],
	"severity": "critical",
	"level": "error",
	"kind": "iac",
	"cwe": ["CWE-284"],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["terraform", "aws", "kms"],
}

findings contains finding if {
	some k in tf.resources("aws_kms_key")
	_has_public_allow(k.block)
	not _has_caller_condition(k.block)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("aws_kms_key %q has a public Allow statement with no kms:CallerAccount or aws:PrincipalOrgID condition.", [k.name]),
		"artifact_uri": k.path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": 1,
		"snippet": sprintf("%s.%s", [k.type, k.name]),
	}
}

_has_public_allow(block) if {
	regex.match(`(?s)"Effect"\s*:\s*"Allow"[\s\S]*?"AWS"\s*:\s*"\*"`, block)
}

_has_public_allow(block) if {
	regex.match(`(?s)"AWS"\s*:\s*"\*"[\s\S]*?"Effect"\s*:\s*"Allow"`, block)
}

_has_caller_condition(block) if {
	regex.match(`(?i)kms:CallerAccount`, block)
}

_has_caller_condition(block) if {
	regex.match(`(?i)aws:PrincipalOrgID`, block)
}
