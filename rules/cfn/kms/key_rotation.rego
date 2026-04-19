# Adapted from https://github.com/fugue/regula (FG_R00036).
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.fugue_cfn_kms_key_rotation

import rego.v1

import data.vulnetix.fugue.cfn

metadata := {
	"id": "FUGUE-CFN-KMS-01",
	"name": "KMS CMK rotation should be enabled",
	"description": "KMS CMK rotation should be enabled. Rotating encryption keys helps reduce the potential impact of a compromised key as the old key cannot be used to access the data.",
	"help_uri": "https://github.com/fugue/regula",
	"languages": ["yaml", "json"],
	"severity": "medium",
	"level": "warning",
	"kind": "iac",
	"cwe": ["CWE-320"],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["cloudformation", "aws", "kms", "encryption"],
}

findings contains finding if {
	some r in cfn.resources("AWS::KMS::Key")
	props := cfn.properties(r)
	not props.EnableKeyRotation == true
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("KMS Key %q does not have EnableKeyRotation set to true.", [r.logical_id]),
		"artifact_uri": r.path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": 1,
		"snippet": sprintf("AWS::KMS::Key/%s", [r.logical_id]),
	}
}
