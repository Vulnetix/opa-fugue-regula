# Adapted from https://github.com/fugue/regula (FG_R00086).
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.fugue_tf_aws_iam_08

import rego.v1

import data.vulnetix.fugue.tf

metadata := {
	"id": "FUGUE-TF-AWS-IAM-08",
	"name": "IAM password policies should be PCI compliant",
	"description": "Password policies should require passwords to be at least 7 characters long and include both alphabetic and numeric characters.",
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
	"tags": ["terraform", "aws", "iam", "password", "pci"],
}

findings contains finding if {
	some r in tf.resources("aws_iam_account_password_policy")
	not _pci_compliant(r.block)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("IAM password policy %q is not PCI compliant (require_numbers + require_lowercase_characters + minimum_password_length >= 7).", [r.name]),
		"artifact_uri": r.path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": 1,
		"snippet": sprintf("%s.%s", [r.type, r.name]),
	}
}

_pci_compliant(block) if {
	tf.bool_attr(block, "require_numbers") == true
	tf.bool_attr(block, "require_lowercase_characters") == true
	tf.number_attr(block, "minimum_password_length") >= 7
}
