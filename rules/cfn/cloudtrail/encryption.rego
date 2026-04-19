# Adapted from https://github.com/fugue/regula (FG_R00035).
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.fugue_cfn_cloudtrail_encryption

import rego.v1

import data.vulnetix.fugue.cfn

metadata := {
	"id": "FUGUE-CFN-CT-02",
	"name": "CloudTrail log files should be encrypted using KMS CMKs",
	"description": "CloudTrail log files should be encrypted using KMS CMKs. Using SSE-KMS (customer-managed key) instead of the default SSE-S3 provides key rotation control and auditing visibility into key usage.",
	"help_uri": "https://github.com/fugue/regula",
	"languages": ["yaml", "json"],
	"severity": "high",
	"level": "error",
	"kind": "iac",
	"cwe": ["CWE-311"],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["cloudformation", "aws", "cloudtrail", "encryption"],
}

findings contains finding if {
	some r in cfn.resources("AWS::CloudTrail::Trail")
	props := cfn.properties(r)
	not _has_kms(props)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("CloudTrail Trail %q does not specify a KMSKeyId for log file encryption.", [r.logical_id]),
		"artifact_uri": r.path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": 1,
		"snippet": sprintf("AWS::CloudTrail::Trail/%s", [r.logical_id]),
	}
}

_has_kms(props) if {
	props.KMSKeyId != null
}
