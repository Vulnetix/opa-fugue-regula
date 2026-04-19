# Adapted from https://github.com/fugue/regula (FG_R00240).
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.fugue_tf_aws_cw_01

import rego.v1

import data.vulnetix.fugue.tf

metadata := {
	"id": "FUGUE-TF-AWS-CW-01",
	"name": "CloudWatch alarms should have at least one action configured",
	"description": "CloudWatch alarms should have at least one alarm action, one INSUFFICIENT_DATA action, or one OK action enabled so state changes can invoke notifications.",
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
	"tags": ["terraform", "aws", "cloudwatch", "alarm"],
}

findings contains finding if {
	some r in tf.resources("aws_cloudwatch_metric_alarm")
	not _has_any_action(r.block)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("CloudWatch alarm %q has no alarm_actions, ok_actions, or insufficient_data_actions.", [r.name]),
		"artifact_uri": r.path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": 1,
		"snippet": sprintf("%s.%s", [r.type, r.name]),
	}
}

_has_any_action(block) if tf.has_key(block, "alarm_actions")

_has_any_action(block) if tf.has_key(block, "ok_actions")

_has_any_action(block) if tf.has_key(block, "insufficient_data_actions")
