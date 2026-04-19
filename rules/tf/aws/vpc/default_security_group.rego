# Adapted from https://github.com/fugue/regula (FG_R00089).
# Ported to the Vulnetix Rego input schema (input.file_contents).
# Simplified: flags aws_default_security_group resources that declare any ingress or egress block with a cidr_block.

package vulnetix.rules.fugue_tf_aws_vpc_01

import rego.v1

import data.vulnetix.fugue.tf

metadata := {
	"id": "FUGUE-TF-AWS-VPC-01",
	"name": "VPC default security group should restrict all traffic",
	"description": "Configuring VPC default security groups to restrict all traffic encourages least-privilege security group development.",
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
	"tags": ["terraform", "aws", "vpc", "security_group"],
}

findings contains finding if {
	some sg in tf.resources("aws_default_security_group")
	_has_open_rule(sg.block)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("aws_default_security_group %q declares ingress/egress rules that permit traffic.", [sg.name]),
		"artifact_uri": sg.path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": 1,
		"snippet": sprintf("%s.%s", [sg.type, sg.name]),
	}
}

_has_open_rule(block) if {
	some rule in tf.sub_blocks(block, "ingress")
	cidrs := tf.string_list_attr(rule, "cidr_blocks")
	count(cidrs) > 0
}

_has_open_rule(block) if {
	some rule in tf.sub_blocks(block, "egress")
	cidrs := tf.string_list_attr(rule, "cidr_blocks")
	count(cidrs) > 0
	not _only_loopback(cidrs)
}

_only_loopback(cidrs) if {
	count(cidrs) == 1
	cidrs[0] == "127.0.0.1/32"
}
