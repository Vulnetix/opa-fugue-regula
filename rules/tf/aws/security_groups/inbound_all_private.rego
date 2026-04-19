# Adapted from https://github.com/fugue/regula (FG_R00350).
# Ported to the Vulnetix Rego input schema (input.file_contents).
# Simplified: flags aws_security_group ingress rules with all-ports from any CIDR (not self-only).

package vulnetix.rules.fugue_tf_aws_sg_04

import rego.v1

import data.vulnetix.fugue.tf

metadata := {
	"id": "FUGUE-TF-AWS-SG-04",
	"name": "VPC security group inbound rules should not permit ingress from any address to all ports",
	"description": "Security groups should not explicitly allow all inbound ports from any CIDR.",
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
	"tags": ["terraform", "aws", "security_group"],
}

findings contains finding if {
	some sg in tf.resources("aws_security_group")
	some rule in tf.sub_blocks(sg.block, "ingress")
	_rule_all_ports(rule)
	_has_cidr(rule)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("aws_security_group %q has an all-ports ingress rule with a CIDR block.", [sg.name]),
		"artifact_uri": sg.path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": 1,
		"snippet": sprintf("%s.%s", [sg.type, sg.name]),
	}
}

_rule_all_ports(block) if {
	from := tf.number_attr(block, "from_port")
	to := tf.number_attr(block, "to_port")
	from == 0
	to >= 65535
}

_rule_all_ports(block) if tf.string_attr(block, "protocol") == "-1"

_has_cidr(block) if {
	cidrs := tf.string_list_attr(block, "cidr_blocks")
	count(cidrs) > 0
}

_has_cidr(block) if {
	cidrs := tf.string_list_attr(block, "ipv6_cidr_blocks")
	count(cidrs) > 0
}
