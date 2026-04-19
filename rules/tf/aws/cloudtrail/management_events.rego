# Adapted from https://github.com/fugue/regula (FG_R00237).
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.fugue_tf_aws_ct_04

import rego.v1

import data.vulnetix.fugue.tf

metadata := {
	"id": "FUGUE-TF-AWS-CT-04",
	"name": "CloudTrail trails should log management events",
	"description": "CloudTrail trails should be configured to log management events to provide visibility into management operations performed on resources.",
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
	some es in tf.sub_blocks(r.block, "event_selector")
	tf.bool_attr(es, "include_management_events") == false
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("CloudTrail %q has event_selector with include_management_events = false.", [r.name]),
		"artifact_uri": r.path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": 1,
		"snippet": sprintf("%s.%s", [r.type, r.name]),
	}
}
