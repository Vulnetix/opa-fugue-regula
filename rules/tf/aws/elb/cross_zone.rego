# Adapted from https://github.com/fugue/regula (FG_R00043).
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.fugue_tf_aws_elb_02

import rego.v1

import data.vulnetix.fugue.tf

metadata := {
	"id": "FUGUE-TF-AWS-ELB-02",
	"name": "ELBv1 cross-zone load balancing should be enabled",
	"description": "Cross-zone load balancing reduces the risk of failure at a single location as the load balancer distributes traffic across availability zones.",
	"help_uri": "https://github.com/fugue/regula",
	"languages": ["terraform", "hcl"],
	"severity": "medium",
	"level": "warning",
	"kind": "iac",
	"cwe": ["CWE-1188"],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["terraform", "aws", "elb", "availability"],
}

findings contains finding if {
	some r in tf.resources("aws_elb")
	tf.is_not_true(r.block, "cross_zone_load_balancing")
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("ELB %q does not enable cross_zone_load_balancing.", [r.name]),
		"artifact_uri": r.path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": 1,
		"snippet": sprintf("%s.%s", [r.type, r.name]),
	}
}
