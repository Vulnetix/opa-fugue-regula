# Adapted from https://github.com/fugue/regula (FG_R00271).
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.fugue_tf_aws_ec2_02

import rego.v1

import data.vulnetix.fugue.tf

metadata := {
	"id": "FUGUE-TF-AWS-EC2-02",
	"name": "EC2 instances should not have a public IP association",
	"description": "Publicly accessible EC2 instances are reachable over the internet even with NACLs or security groups. If protections are removed, instances may be vulnerable to attack.",
	"help_uri": "https://github.com/fugue/regula",
	"languages": ["terraform", "hcl"],
	"severity": "medium",
	"level": "warning",
	"kind": "iac",
	"cwe": ["CWE-284"],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["terraform", "aws", "ec2", "public"],
}

findings contains finding if {
	some r in tf.resources("aws_instance")
	tf.bool_attr(r.block, "associate_public_ip_address") == true
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("EC2 instance %q sets associate_public_ip_address = true.", [r.name]),
		"artifact_uri": r.path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": 1,
		"snippet": sprintf("%s.%s", [r.type, r.name]),
	}
}
