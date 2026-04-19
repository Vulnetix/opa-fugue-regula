# Adapted from https://github.com/fugue/regula (FG_R00103).
# Ported to the Vulnetix Rego input schema (input.file_contents).
# Simplified: flags aws_security_group attached to an aws_instance that has ingress all-ports from 0.0.0.0/0.

package vulnetix.rules.fugue_tf_aws_sg_41

import rego.v1

import data.vulnetix.fugue.tf

metadata := {
	"id": "FUGUE-TF-AWS-SG-41",
	"name": "Security groups on EC2 instances should not permit ingress from 0.0.0.0/0 to all ports",
	"description": "EC2 security groups should permit access only to necessary ports to prevent access to potentially vulnerable services on other ports.",
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
	"tags": ["terraform", "aws", "security_group", "ec2"],
}

findings contains finding if {
	some sg in tf.resources("aws_security_group")
	_is_ec2_connected(sg.name)
	some rule in tf.sub_blocks(sg.block, "ingress")
	_rule_all_ports(rule)
	_rule_zero_cidr(rule)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("aws_security_group %q (on EC2) allows ingress from 0.0.0.0/0 to all ports.", [sg.name]),
		"artifact_uri": sg.path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": 1,
		"snippet": sprintf("%s.%s", [sg.type, sg.name]),
	}
}

_is_ec2_connected(name) if {
	some i in tf.resources("aws_instance")
	tf.references(i.block, "aws_security_group", name)
}

_is_ec2_connected(name) if {
	some i in tf.resources("aws_launch_configuration")
	tf.references(i.block, "aws_security_group", name)
}

_is_ec2_connected(name) if {
	some i in tf.resources("aws_launch_template")
	tf.references(i.block, "aws_security_group", name)
}

_rule_all_ports(block) if {
	from := tf.number_attr(block, "from_port")
	to := tf.number_attr(block, "to_port")
	from == 0
	to >= 65535
}

_rule_all_ports(block) if tf.string_attr(block, "protocol") == "-1"

_rule_zero_cidr(block) if {
	cidrs := tf.string_list_attr(block, "cidr_blocks")
	some c in cidrs
	c == "0.0.0.0/0"
}

_rule_zero_cidr(block) if {
	cidrs := tf.string_list_attr(block, "ipv6_cidr_blocks")
	some c in cidrs
	c == "::/0"
}
