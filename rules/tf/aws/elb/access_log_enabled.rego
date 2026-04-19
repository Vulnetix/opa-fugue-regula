# Adapted from https://github.com/fugue/regula (FG_R00066).
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.fugue_tf_aws_elb_01

import rego.v1

import data.vulnetix.fugue.tf

metadata := {
	"id": "FUGUE-TF-AWS-ELB-01",
	"name": "Load balancer access logging should be enabled",
	"description": "Load balancer access logs record information about every HTTP and TCP request processed. Access logging should be enabled to analyze statistics, diagnose issues, and retain data.",
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
	"tags": ["terraform", "aws", "elb", "logging"],
}

findings contains finding if {
	some ty in {"aws_elb", "aws_lb", "aws_alb"}
	some r in tf.resources(ty)
	not _access_logs_enabled(r.block)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Load balancer %q (%s) does not enable access_logs.", [r.name, r.type]),
		"artifact_uri": r.path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": 1,
		"snippet": sprintf("%s.%s", [r.type, r.name]),
	}
}

_access_logs_enabled(block) if {
	some al in tf.sub_blocks(block, "access_logs")
	tf.bool_attr(al, "enabled") == true
}
