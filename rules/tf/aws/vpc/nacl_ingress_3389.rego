# Adapted from https://github.com/fugue/regula (FG_R00358).
# Ported to the Vulnetix Rego input schema (input.file_contents).
# Simplified: flags aws_network_acl with an ingress block allowing port 3389 from 0.0.0.0/0, and standalone aws_network_acl_rule of the same.

package vulnetix.rules.fugue_tf_aws_vpc_03

import rego.v1

import data.vulnetix.fugue.tf

metadata := {
	"id": "FUGUE-TF-AWS-VPC-03",
	"name": "VPC network ACLs should not allow ingress from 0.0.0.0/0 to port 3389 (RDP)",
	"description": "Public access to remote server administration ports such as 3389 increases attack surface and unnecessarily raises the risk of compromise.",
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
	"tags": ["terraform", "aws", "vpc", "nacl"],
}

findings contains finding if {
	some nacl in tf.resources("aws_network_acl")
	some rule in tf.sub_blocks(nacl.block, "ingress")
	lower(tf.string_attr(rule, "action")) == "allow"
	tf.string_attr(rule, "cidr_block") == "0.0.0.0/0"
	_covers_port(rule, 3389)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("aws_network_acl %q allows ingress from 0.0.0.0/0 to port 3389.", [nacl.name]),
		"artifact_uri": nacl.path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": 1,
		"snippet": sprintf("%s.%s", [nacl.type, nacl.name]),
	}
}

findings contains finding if {
	some r in tf.resources("aws_network_acl_rule")
	lower(tf.string_attr(r.block, "rule_action")) == "allow"
	tf.is_not_true(r.block, "egress")
	tf.string_attr(r.block, "cidr_block") == "0.0.0.0/0"
	_covers_port(r.block, 3389)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("aws_network_acl_rule %q allows ingress from 0.0.0.0/0 to port 3389.", [r.name]),
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
