# Adapted from https://github.com/fugue/regula (FG_R00045).
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.fugue_tf_aws_sg_39

import rego.v1

import data.vulnetix.fugue.tf

metadata := {
	"id": "FUGUE-TF-AWS-SG-39",
	"name": "VPC security group inbound rules should not permit ingress from 0.0.0.0/0 to all ports and protocols",
	"description": "Security groups should not allow unrestricted ingress from 0.0.0.0/0 to all ports. Removing unfettered connectivity reduces a server's exposure to risk.",
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
	_rule_zero_cidr(rule)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("aws_security_group %q allows ingress from 0.0.0.0/0 to all ports.", [sg.name]),
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
