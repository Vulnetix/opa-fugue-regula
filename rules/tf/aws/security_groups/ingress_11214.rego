# Adapted from https://github.com/fugue/regula (FG_R00242).
# Ported to the Vulnetix Rego input schema (input.file_contents).
# Simplified: flags aws_security_group with ingress covering port 11214 from 0.0.0.0/0.

package vulnetix.rules.fugue_tf_aws_sg_05

import rego.v1

import data.vulnetix.fugue.tf

metadata := {
	"id": "FUGUE-TF-AWS-SG-05",
	"name": "Security group rules should not permit ingress from 0.0.0.0/0 to TCP/UDP port 11214 (Memcached SSL)",
	"description": "Unrestricted ingress from the internet to port 11214 exposes Memcached SSL to remote attack.",
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
	_covers_port(rule, 11214)
	_rule_zero_cidr(rule)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("aws_security_group %q allows ingress from 0.0.0.0/0 to port 11214.", [sg.name]),
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
	_covers_port(r.block, 11214)
	_rule_zero_cidr(r.block)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("aws_security_group_rule %q allows ingress from 0.0.0.0/0 to port 11214.", [r.name]),
		"artifact_uri": r.path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": 1,
		"snippet": sprintf("%s.%s", [r.type, r.name]),
	}
}

_covers_port(block, port) if {
	from := tf.number_attr(block, "from_port")
	to := tf.number_attr(block, "to_port")
	from <= port
	port <= to
}

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
