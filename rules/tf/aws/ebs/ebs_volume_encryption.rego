# Adapted from https://github.com/fugue/regula (FG_R00016).
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.fugue_tf_aws_ebs_01

import rego.v1

import data.vulnetix.fugue.tf

metadata := {
	"id": "FUGUE-TF-AWS-EBS-01",
	"name": "EBS volume encryption should be enabled",
	"description": "Enabling encryption on EBS volumes protects data at rest inside the volume, in transit between the volume and the instance, in snapshots, and in volumes created from those snapshots.",
	"help_uri": "https://github.com/fugue/regula",
	"languages": ["terraform", "hcl"],
	"severity": "high",
	"level": "error",
	"kind": "iac",
	"cwe": ["CWE-311"],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["terraform", "aws", "ebs", "encryption"],
}

findings contains finding if {
	some r in tf.resources("aws_ebs_volume")
	tf.is_not_true(r.block, "encrypted")
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("EBS volume %q is not encrypted.", [r.name]),
		"artifact_uri": r.path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": 1,
		"snippet": sprintf("%s.%s", [r.type, r.name]),
	}
}
