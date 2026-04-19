# Adapted from https://github.com/fugue/regula (FG_R00029).
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.fugue_cfn_cloudtrail_cloudwatch

import rego.v1

import data.vulnetix.fugue.cfn

metadata := {
	"id": "FUGUE-CFN-CT-01",
	"name": "CloudTrail trails should have CloudWatch log integration",
	"description": "CloudTrail trails should have CloudWatch log integration enabled. Sending CloudTrail log events to CloudWatch Logs allows metric filters and alarms that trigger on anomalous or suspicious API activity.",
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
	not _has_cloudwatch(props)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("CloudTrail Trail %q does not have both CloudWatchLogsLogGroupArn and CloudWatchLogsRoleArn configured.", [r.logical_id]),
		"artifact_uri": r.path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": 1,
		"snippet": sprintf("AWS::CloudTrail::Trail/%s", [r.logical_id]),
	}
}

_has_cloudwatch(props) if {
	props.CloudWatchLogsLogGroupArn != null
	props.CloudWatchLogsRoleArn != null
}
