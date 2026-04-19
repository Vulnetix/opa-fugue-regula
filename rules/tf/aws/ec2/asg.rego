# Adapted from https://github.com/fugue/regula (FG_R00014).
# Ported to the Vulnetix Rego input schema (input.file_contents).
# Limitation: does not resolve subnet AZs through aws_subnet cross-references.

package vulnetix.rules.fugue_tf_aws_ec2_01

import rego.v1

import data.vulnetix.fugue.tf

metadata := {
	"id": "FUGUE-TF-AWS-EC2-01",
	"name": "Auto Scaling groups should span two or more availability zones",
	"description": "Auto Scaling groups that span two or more availability zones promote redundancy to help ensure availability during an adverse situation.",
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
	"tags": ["terraform", "aws", "ec2", "asg", "availability"],
}

findings contains finding if {
	some r in tf.resources("aws_autoscaling_group")
	not _has_multi_az(r.block)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Auto Scaling group %q does not span two or more availability zones (availability_zones or vpc_zone_identifier).", [r.name]),
		"artifact_uri": r.path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": 1,
		"snippet": sprintf("%s.%s", [r.type, r.name]),
	}
}

_has_multi_az(block) if {
	azs := tf.string_list_attr(block, "availability_zones")
	count(azs) >= 2
}

_has_multi_az(block) if {
	# Multiple subnets usually means multiple AZs
	subs := tf.string_list_attr(block, "vpc_zone_identifier")
	count(subs) >= 2
}

_has_multi_az(block) if {
	# Literal HCL list with multiple references
	matches := regex.find_all_string_submatch_n(`vpc_zone_identifier\s*=\s*\[([^\]]+)\]`, block, 1)
	count(matches) > 0
	refs := regex.find_n(`aws_subnet\.[A-Za-z_][A-Za-z0-9_]*`, matches[0][1], -1)
	unique := {x | some x in refs}
	count(unique) >= 2
}
