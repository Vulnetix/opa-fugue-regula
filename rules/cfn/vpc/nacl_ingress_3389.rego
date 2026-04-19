# Adapted from https://github.com/fugue/regula (FG_R00359).
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.fugue_cfn_vpc_nacl_ingress_3389

import rego.v1

import data.vulnetix.fugue.cfn

metadata := {
	"id": "FUGUE-CFN-VPC-06",
	"name": "VPC NACLs should not allow 0.0.0.0/0 ingress to port 3389",
	"description": "VPC network ACLs should not allow ingress from 0.0.0.0/0 to port 3389. Public access to remote server administration ports such as 22 and 3389 increases resource attack surface.",
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
	"tags": ["cloudformation", "aws", "vpc", "nacl", "rdp"],
}

_zero_cidr(entry) if {
	entry.CidrBlock == "0.0.0.0/0"
}

_zero_cidr(entry) if {
	entry.Ipv6CidrBlock == "::/0"
}

_is_ingress(entry) if {
	not entry.Egress == true
}

_includes_port(entry, port) if {
	pr := entry.PortRange
	is_number(pr.From)
	is_number(pr.To)
	pr.From <= port
	pr.To >= port
}

_all_protocols(entry) if {
	entry.Protocol == -1
}

_all_protocols(entry) if {
	entry.Protocol == "-1"
}

_is_allow(entry) if {
	entry.RuleAction == "allow"
}

_nacl_entry_hits(entry, port) if {
	_is_ingress(entry)
	_is_allow(entry)
	_zero_cidr(entry)
	_includes_port(entry, port)
}

_nacl_entry_hits(entry, _) if {
	_is_ingress(entry)
	_is_allow(entry)
	_zero_cidr(entry)
	_all_protocols(entry)
}

_nacl_targets(entry_props, nacl_entry) if {
	ref := entry_props.NetworkAclId
	is_object(ref)
	ref.Ref == nacl_entry.logical_id
}

_nacl_targets(entry_props, nacl_entry) if {
	entry_props.NetworkAclId == nacl_entry.logical_id
}

_nacl_allows_port(nacl_entry, port) if {
	some e in cfn.resources("AWS::EC2::NetworkAclEntry")
	ep := cfn.properties(e)
	_nacl_targets(ep, nacl_entry)
	_nacl_entry_hits(ep, port)
}

findings contains finding if {
	some r in cfn.resources("AWS::EC2::NetworkAcl")
	_nacl_allows_port(r, 3389)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("NetworkAcl %q has an entry allowing 0.0.0.0/0 ingress to port 3389.", [r.logical_id]),
		"artifact_uri": r.path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": 1,
		"snippet": sprintf("AWS::EC2::NetworkAcl/%s", [r.logical_id]),
	}
}
