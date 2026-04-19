# Adapted from https://github.com/fugue/regula (FG_R00054).
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.fugue_tf_aws_vpc_04

import rego.v1

import data.vulnetix.fugue.tf

metadata := {
	"id": "FUGUE-TF-AWS-VPC-04",
	"name": "VPC flow logging should be enabled",
	"description": "VPC Flow Logs provide visibility into network traffic that traverses the VPC; enable them to detect anomalous traffic.",
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
	"tags": ["terraform", "aws", "vpc", "logging"],
}

findings contains finding if {
	some v in tf.resources("aws_vpc")
	not _has_flow_log(v.name)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("aws_vpc %q has no associated aws_flow_log.", [v.name]),
		"artifact_uri": v.path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": 1,
		"snippet": sprintf("%s.%s", [v.type, v.name]),
	}
}

_has_flow_log(vpc_name) if {
	some fl in tf.resources("aws_flow_log")
	tf.references(fl.block, "aws_vpc", vpc_name)
}
