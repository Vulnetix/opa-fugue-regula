# Adapted from https://github.com/fugue/regula (FG_R00102).
# Ported to the Vulnetix Rego input schema (input.file_contents).
# Simplified: flags any aws_security_group referenced by an aws_elb/aws_lb that has an ingress rule covering all ports.

package vulnetix.rules.fugue_tf_aws_sg_02

import rego.v1

import data.vulnetix.fugue.tf

metadata := {
	"id": "FUGUE-TF-AWS-SG-02",
	"name": "ELB listener security groups should not permit all ports",
	"description": "ELB security groups should permit access only to necessary ports to prevent access to potentially vulnerable services on other ports.",
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
	"tags": ["terraform", "aws", "security_group", "elb"],
}

findings contains finding if {
	some sg in tf.resources("aws_security_group")
	_is_elb_connected(sg.name)
	some rule in tf.sub_blocks(sg.block, "ingress")
	_rule_all_ports(rule)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("aws_security_group %q attached to an ELB has an all-ports ingress rule.", [sg.name]),
		"artifact_uri": sg.path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": 1,
		"snippet": sprintf("%s.%s", [sg.type, sg.name]),
	}
}

_is_elb_connected(name) if {
	some lb in tf.resources("aws_elb")
	tf.references(lb.block, "aws_security_group", name)
}

_is_elb_connected(name) if {
	some lb in tf.resources("aws_lb")
	tf.references(lb.block, "aws_security_group", name)
}

_is_elb_connected(name) if {
	some lb in tf.resources("aws_alb")
	tf.references(lb.block, "aws_security_group", name)
}

_rule_all_ports(block) if {
	from := tf.number_attr(block, "from_port")
	to := tf.number_attr(block, "to_port")
	from == 0
	to >= 65535
}

_rule_all_ports(block) if tf.string_attr(block, "protocol") == "-1"
