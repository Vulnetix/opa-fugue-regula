# Adapted from https://github.com/fugue/regula (FG_R00029).
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.fugue_tf_aws_ct_01

import rego.v1

import data.vulnetix.fugue.tf

metadata := {
	"id": "FUGUE-TF-AWS-CT-01",
	"name": "CloudTrail trails should have CloudWatch log integration enabled",
	"description": "CloudTrail trails should be configured to send log events to CloudWatch Logs so that users can create metric filters and alarms.",
	"help_uri": "https://github.com/fugue/regula",
	"languages": ["terraform", "hcl"],
	"severity": "medium",
	"level": "warning",
	"kind": "iac",
	"cwe": ["CWE-778"],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["terraform", "aws", "cloudtrail", "logging"],
}

findings contains finding if {
	some r in tf.resources("aws_cloudtrail")
	not _has_integration(r.block)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("CloudTrail %q lacks CloudWatch log integration (cloud_watch_logs_group_arn and cloud_watch_logs_role_arn).", [r.name]),
		"artifact_uri": r.path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": 1,
		"snippet": sprintf("%s.%s", [r.type, r.name]),
	}
}

_has_integration(block) if {
	tf.has_key(block, "cloud_watch_logs_group_arn")
	tf.has_key(block, "cloud_watch_logs_role_arn")
}
