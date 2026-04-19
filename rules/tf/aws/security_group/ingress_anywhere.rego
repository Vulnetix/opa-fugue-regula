# Adapted from https://github.com/fugue/regula (FG_R00377).
# Ported to the Vulnetix Rego input schema (input.file_contents).
# Simplified: scans aws_security_group ingress sub-blocks; flags 0.0.0.0/0 ingress to ports other than 80 and 443.

package vulnetix.rules.fugue_tf_aws_sg_01

import rego.v1

import data.vulnetix.fugue.tf

metadata := {
	"id": "FUGUE-TF-AWS-SG-01",
	"name": "VPC security group rules should not permit ingress from 0.0.0.0/0 except to ports 80 and 443",
	"description": "VPC firewall rules should not permit unrestricted access from the internet, except for HTTP (80) and HTTPS (443).",
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

whitelisted_ports := {80, 443}

findings contains finding if {
	some sg in tf.resources("aws_security_group")
	some rule in tf.sub_blocks(sg.block, "ingress")
	_rule_zero_cidr(rule)
	not _rule_whitelisted(rule)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("aws_security_group %q has an ingress rule from 0.0.0.0/0 not whitelisted to port 80/443.", [sg.name]),
		"artifact_uri": sg.path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": 1,
		"snippet": sprintf("%s.%s", [sg.type, sg.name]),
	}
}

_rule_zero_cidr(rule) if {
	cidrs := tf.string_list_attr(rule, "cidr_blocks")
	some c in cidrs
	c == "0.0.0.0/0"
}

_rule_whitelisted(rule) if {
	from := tf.number_attr(rule, "from_port")
	to := tf.number_attr(rule, "to_port")
	from == to
	whitelisted_ports[from]
}
