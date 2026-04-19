# Adapted from https://github.com/fugue/regula (FG_R00085).
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.fugue_cfn_vpc_ingress_22

import rego.v1

import data.vulnetix.fugue.cfn

metadata := {
	"id": "FUGUE-CFN-VPC-03",
	"name": "VPC SGs should not permit 0.0.0.0/0 ingress to port 22 (SSH)",
	"description": "VPC security group rules should not permit ingress from '0.0.0.0/0' to TCP/UDP port 22 (SSH). Removing unfettered connectivity to remote console services such as SSH reduces a server's exposure to risk.",
	"help_uri": "https://github.com/fugue/regula",
	"languages": ["yaml", "json"],
	"severity": "high",
	"level": "error",
	"kind": "iac",
	"cwe": ["CWE-284"],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["cloudformation", "aws", "vpc", "security-group", "ssh"],
}

_zero_cidr(rule) if {
	rule.CidrIp == "0.0.0.0/0"
}

_zero_cidr(rule) if {
	rule.CidrIpv6 == "::/0"
}

_includes_port(rule, port) if {
	to := rule.ToPort
	from := rule.FromPort
	is_number(to)
	is_number(from)
	from <= port
	to >= port
}

_is_all_protocols(rule) if {
	p := rule.IpProtocol
	p == "-1"
}

_is_tcp_or_udp(rule) if {
	p := rule.IpProtocol
	p == "tcp"
}

_is_tcp_or_udp(rule) if {
	p := rule.IpProtocol
	p == "udp"
}

_rule_hits_port(rule, port) if {
	_zero_cidr(rule)
	_is_tcp_or_udp(rule)
	_includes_port(rule, port)
}

_rule_hits_port(rule, _) if {
	_zero_cidr(rule)
	_is_all_protocols(rule)
}

# Standalone ingress rule.
findings contains finding if {
	some r in cfn.resources("AWS::EC2::SecurityGroupIngress")
	props := cfn.properties(r)
	_rule_hits_port(props, 22)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("SecurityGroupIngress %q permits 0.0.0.0/0 to port 22 (SSH).", [r.logical_id]),
		"artifact_uri": r.path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": 1,
		"snippet": sprintf("AWS::EC2::SecurityGroupIngress/%s", [r.logical_id]),
	}
}

# Inline ingress in SG resource.
findings contains finding if {
	some r in cfn.resources("AWS::EC2::SecurityGroup")
	props := cfn.properties(r)
	some rule in props.SecurityGroupIngress
	_rule_hits_port(rule, 22)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("SecurityGroup %q has an inline ingress rule permitting 0.0.0.0/0 to port 22 (SSH).", [r.logical_id]),
		"artifact_uri": r.path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": 1,
		"snippet": sprintf("AWS::EC2::SecurityGroup/%s", [r.logical_id]),
	}
}
