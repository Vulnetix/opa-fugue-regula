# Adapted from https://github.com/fugue/regula (FG_R00190).
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.fugue_tf_az_net_inbound_3389

import rego.v1

import data.vulnetix.fugue.tf

metadata := {
	"id": "FUGUE-TF-AZ-NET-04",
	"name": "NSGs should not permit ingress from 0.0.0.0/0 to TCP/UDP port 3389 (RDP)",
	"description": "Virtual Network security groups should not permit ingress from '0.0.0.0/0' to TCP/UDP port 3389 (RDP). The potential security problem with using RDP over the Internet is that attackers can use various brute force techniques to gain access to Azure Virtual Machines.",
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
	"tags": ["terraform", "azure", "network", "rdp"],
}

findings contains finding if {
	some r in tf.resources("azurerm_network_security_rule")
	_bad_inbound(r.block, 3389)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("NSG rule %q permits inbound RDP (port 3389) from 0.0.0.0/0.", [r.name]),
		"artifact_uri": r.path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": 1,
		"snippet": sprintf("%s.%s", [r.type, r.name]),
	}
}

findings contains finding if {
	some sg in tf.resources("azurerm_network_security_group")
	some rule in tf.sub_blocks(sg.block, "security_rule")
	_bad_inbound(rule, 3389)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("NSG %q has an inline security_rule permitting RDP (port 3389) from 0.0.0.0/0.", [sg.name]),
		"artifact_uri": sg.path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": 1,
		"snippet": sprintf("%s.%s", [sg.type, sg.name]),
	}
}

_bad_inbound(block, port) if {
	tf.string_attr(block, "access") == "Allow"
	tf.string_attr(block, "direction") == "Inbound"
	_source_is_any(block)
	_dest_in_port(block, port)
}

_source_is_any(block) if _is_any(tf.string_attr(block, "source_address_prefix"))

_source_is_any(block) if {
	prefixes := tf.string_list_attr(block, "source_address_prefixes")
	some p in prefixes
	_is_any(p)
}

_is_any(p) if p in {"*", "0.0.0.0", "<nw>/0", "/0", "internet", "any", "Internet", "Any"}

_dest_in_port(block, port) if _in_range(port, tf.string_attr(block, "destination_port_range"))

_dest_in_port(block, port) if {
	ranges := tf.string_list_attr(block, "destination_port_ranges")
	some r in ranges
	_in_range(port, r)
}

_in_range(_, range) if range == "*"

_in_range(port, range) if format_int(port, 10) == range

_in_range(port, range) if {
	regex.match(`^[0-9]+-[0-9]+$`, range)
	parts := split(range, "-")
	lo := to_number(parts[0])
	hi := to_number(parts[1])
	port >= lo
	port <= hi
}
