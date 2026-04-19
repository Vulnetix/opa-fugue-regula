# Adapted from https://github.com/fugue/regula (FG_R00036).
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.fugue_tf_aws_kms_02

import rego.v1

import data.vulnetix.fugue.tf

metadata := {
	"id": "FUGUE-TF-AWS-KMS-02",
	"name": "KMS CMK rotation should be enabled",
	"description": "It is recommended that users enable rotation for customer-managed KMS Customer Master Keys (CMKs). Rotating encryption keys helps reduce the potential impact of a compromised key.",
	"help_uri": "https://github.com/fugue/regula",
	"languages": ["terraform", "hcl"],
	"severity": "medium",
	"level": "warning",
	"kind": "iac",
	"cwe": ["CWE-324"],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["terraform", "aws", "kms"],
}

findings contains finding if {
	some k in tf.resources("aws_kms_key")
	_is_symmetric(k.block)
	tf.is_not_true(k.block, "enable_key_rotation")
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("aws_kms_key %q does not have enable_key_rotation = true.", [k.name]),
		"artifact_uri": k.path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": 1,
		"snippet": sprintf("%s.%s", [k.type, k.name]),
	}
}

_is_symmetric(block) if {
	not tf.has_key(block, "customer_master_key_spec")
}

_is_symmetric(block) if {
	spec := tf.string_attr(block, "customer_master_key_spec")
	startswith(spec, "SYMMETRIC")
}
