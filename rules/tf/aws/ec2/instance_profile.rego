# Adapted from https://github.com/fugue/regula (FG_R00253).
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.fugue_tf_aws_ec2_03

import rego.v1

import data.vulnetix.fugue.tf

metadata := {
	"id": "FUGUE-TF-AWS-EC2-03",
	"name": "EC2 instances should use IAM roles and instance profiles",
	"description": "EC2 instances should use IAM roles and instance profiles instead of IAM access keys to limit the risk of access key exposure.",
	"help_uri": "https://github.com/fugue/regula",
	"languages": ["terraform", "hcl"],
	"severity": "high",
	"level": "error",
	"kind": "iac",
	"cwe": ["CWE-522"],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["terraform", "aws", "ec2", "iam"],
}

findings contains finding if {
	some r in tf.resources("aws_instance")
	not tf.has_key(r.block, "iam_instance_profile")
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("EC2 instance %q does not set iam_instance_profile.", [r.name]),
		"artifact_uri": r.path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": 1,
		"snippet": sprintf("%s.%s", [r.type, r.name]),
	}
}
