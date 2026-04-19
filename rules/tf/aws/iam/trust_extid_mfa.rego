# Adapted from https://github.com/fugue/regula (FG_R00255).
# Ported to the Vulnetix Rego input schema (input.file_contents).
# Simplified: flags assume_role_policy that has an AWS ARN principal but no sts:ExternalID or MultiFactorAuthPresent condition.

package vulnetix.rules.fugue_tf_aws_iam_15

import rego.v1

import data.vulnetix.fugue.tf

metadata := {
	"id": "FUGUE-TF-AWS-IAM-15",
	"name": "IAM roles used for trust relationships should have MFA or external IDs",
	"description": "IAM roles that trust other AWS accounts should use additional security measures such as MFA or external IDs to mitigate the confused deputy problem.",
	"help_uri": "https://github.com/fugue/regula",
	"languages": ["terraform", "hcl"],
	"severity": "high",
	"level": "error",
	"kind": "iac",
	"cwe": ["CWE-287"],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["terraform", "aws", "iam", "mfa"],
}

findings contains finding if {
	some r in tf.resources("aws_iam_role")
	_has_aws_principal(r.block)
	not _has_external_id_or_mfa(r.block)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("IAM role %q has a trust policy with an AWS principal but no sts:ExternalID or MFA condition.", [r.name]),
		"artifact_uri": r.path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": 1,
		"snippet": sprintf("%s.%s", [r.type, r.name]),
	}
}

_has_aws_principal(block) if {
	regex.match(`"AWS"\s*:\s*"arn:aws[-0-9a-z]*:iam::`, block)
}

_has_external_id_or_mfa(block) if {
	regex.match(`(?i)sts:ExternalID`, block)
}

_has_external_id_or_mfa(block) if {
	regex.match(`(?i)aws:MultiFactorAuthPresent`, block)
}
