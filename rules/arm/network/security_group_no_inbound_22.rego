# Adapted from https://github.com/fugue/regula (FG_R00191).
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.fugue_arm_network_security_group_no_inbound_22

import rego.v1

import data.vulnetix.fugue.arm

metadata := {
	"id": "FUGUE-ARM-NET-03",
	"name": "Virtual Network security groups should not permit ingress from '0.0.0.0/0' to TCP/UDP port 22 (SSH)",
	"description": "The potential security problem with using SSH over the internet is that attackers can use various brute force techniques to gain access to Azure Virtual Machines. Once the attackers gain access, they can use a virtual machine as a launch point for compromising other machines on the Azure Virtual Network or even attack networked devices outside of Azure.",
	"help_uri": "https://github.com/fugue/regula",
	"languages": ["json"],
	"severity": "high",
	"level": "error",
	"kind": "iac",
	"cwe": ["CWE-284"],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["arm", "azure", "network", "ssh"],
}

_target_port := 22

_any_source(src) if {
	src == "*"
}

_any_source(src) if {
	src == "0.0.0.0/0"
}

_any_source(src) if {
	src == "Internet"
}

_rule_allows_port(rule, port) if {
	p := object.get(rule.properties, "destinationPortRange", "")
	_port_range_includes(p, port)
}

_rule_allows_port(rule, port) if {
	some p in object.get(rule.properties, "destinationPortRanges", [])
	_port_range_includes(p, port)
}

_port_range_includes(range, port) if {
	range == "*"
}

_port_range_includes(range, port) if {
	range == sprintf("%d", [port])
}

_port_range_includes(range, port) if {
	parts := split(range, "-")
	count(parts) == 2
	to_number(parts[0]) <= port
	to_number(parts[1]) >= port
}

_rule_from_any(rule) if {
	src := object.get(rule.properties, "sourceAddressPrefix", "")
	_any_source(src)
}

_rule_from_any(rule) if {
	some src in object.get(rule.properties, "sourceAddressPrefixes", [])
	_any_source(src)
}

_bad_rule(rule, port) if {
	lower(object.get(rule.properties, "access", "")) == "allow"
	lower(object.get(rule.properties, "direction", "")) == "inbound"
	_rule_from_any(rule)
	_rule_allows_port(rule, port)
}

_nsg_has_bad_rule(nsg, port) if {
	some rule in object.get(nsg.resource.properties, "securityRules", [])
	_bad_rule(rule, port)
}

_nsg_has_bad_rule(nsg, port) if {
	some child in object.get(nsg.resource, "resources", [])
	child.type == "securityRules"
	_bad_rule(child, port)
}

_nsg_has_bad_rule(nsg, port) if {
	some sr in arm.resources("Microsoft.Network/networkSecurityGroups/securityRules")
	sr.path == nsg.path
	startswith(sr.resource.name, sprintf("%s/", [nsg.resource.name]))
	_bad_rule(sr.resource, port)
}

findings contains finding if {
	some nsg in arm.resources("Microsoft.Network/networkSecurityGroups")
	_nsg_has_bad_rule(nsg, _target_port)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("NSG %q allows inbound SSH (port 22) from any source.", [nsg.resource.name]),
		"artifact_uri": nsg.path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": 1,
		"snippet": sprintf("%s/%s", [nsg.resource.type, nsg.resource.name]),
	}
}
