# Adapted from https://github.com/fugue/regula (FG_R00013).
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.fugue_tf_aws_elb_03

import rego.v1

import data.vulnetix.fugue.tf

metadata := {
	"id": "FUGUE-TF-AWS-ELB-03",
	"name": "ELBv1 listener protocol should not be HTTP",
	"description": "Communication from an ELB to EC2 instances should be encrypted. ELB listener protocol should not be set to HTTP.",
	"help_uri": "https://github.com/fugue/regula",
	"languages": ["terraform", "hcl"],
	"severity": "high",
	"level": "error",
	"kind": "iac",
	"cwe": ["CWE-319"],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["terraform", "aws", "elb", "tls"],
}

findings contains finding if {
	some r in tf.resources("aws_elb")
	some listener in tf.sub_blocks(r.block, "listener")
	lower(tf.string_attr(listener, "lb_protocol")) == "http"
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("ELB %q listener uses HTTP lb_protocol.", [r.name]),
		"artifact_uri": r.path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": 1,
		"snippet": sprintf("%s.%s", [r.type, r.name]),
	}
}
