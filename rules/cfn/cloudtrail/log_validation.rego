# Adapted from https://github.com/fugue/regula (FG_R00027).
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.fugue_cfn_cloudtrail_log_validation

import rego.v1

import data.vulnetix.fugue.cfn

metadata := {
	"id": "FUGUE-CFN-CT-03",
	"name": "CloudTrail log file validation should be enabled",
	"description": "CloudTrail log file validation should be enabled. Enabling file validation on CloudTrail logs provides additional integrity checking of the log data.",
	"help_uri": "https://github.com/fugue/regula",
	"languages": ["yaml", "json"],
	"severity": "medium",
	"level": "warning",
	"kind": "iac",
	"cwe": ["CWE-778"],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["cloudformation", "aws", "cloudtrail", "logging"],
}

findings contains finding if {
	some r in cfn.resources("AWS::CloudTrail::Trail")
	props := cfn.properties(r)
	not props.EnableLogFileValidation == true
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("CloudTrail Trail %q does not have EnableLogFileValidation set to true.", [r.logical_id]),
		"artifact_uri": r.path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": 1,
		"snippet": sprintf("AWS::CloudTrail::Trail/%s", [r.logical_id]),
	}
}
