# Adapted from https://github.com/fugue/regula (FG_R00044).
# Ported to the Vulnetix Rego input schema (input.file_contents).
# Simplified: flags aws_security_group ingress rules from a public CIDR allowing all ports.

package vulnetix.rules.fugue_tf_aws_sg_03

import rego.v1

import data.vulnetix.fugue.tf

metadata := {
	"id": "FUGUE-TF-AWS-SG-03",
	"name": "VPC security group inbound rules should not permit ingress from a public address to all ports and protocols",
	"description": "Security groups should not allow unrestricted inbound access from the internet.",
	"help_uri": "https://github.com/fugue/regula",
	"languages": ["terraform", "hcl"],
	"severity": "high",
	"level": "error",
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
	_rule_public_cidr(rule)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("aws_security_group %q allows ingress from a public CIDR to all ports.", [sg.name]),
		"artifact_uri": sg.path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": 1,
		"snippet": sprintf("%s.%s", [sg.type, sg.name]),
	}
}

findings contains finding if {
	some r in tf.resources("aws_security_group_rule")
	lower(tf.string_attr(r.block, "type")) == "ingress"
	_rule_all_ports(r.block)
	_rule_public_cidr(r.block)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("aws_security_group_rule %q allows ingress from a public CIDR to all ports.", [r.name]),
		"artifact_uri": r.path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": 1,
		"snippet": sprintf("%s.%s", [r.type, r.name]),
	}
}

_rule_all_ports(block) if {
	from := tf.number_attr(block, "from_port")
	to := tf.number_attr(block, "to_port")
	from == 0
	to >= 65535
}

_rule_all_ports(block) if tf.string_attr(block, "protocol") == "-1"

_rule_public_cidr(block) if {
	cidrs := tf.string_list_attr(block, "cidr_blocks")
	some c in cidrs
	c == "0.0.0.0/0"
}

_rule_public_cidr(block) if {
	cidrs := tf.string_list_attr(block, "ipv6_cidr_blocks")
	some c in cidrs
	c == "::/0"
}
