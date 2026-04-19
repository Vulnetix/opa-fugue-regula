# Adapted from https://github.com/fugue/regula (FG_R00407).
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.fugue_tf_gcp_gce_firewall_port_22

import rego.v1

import data.vulnetix.fugue.tf

metadata := {
	"id": "FUGUE-TF-GCP-GCE-05",
	"name": "Network firewall rules should not permit ingress from 0.0.0.0/0 to port 22 (SSH)",
	"description": "Network firewall rules should not permit ingress from 0.0.0.0/0 to port 22 (SSH). If SSH is open to the internet, attackers can attempt to gain access to VM instances. Removing unfettered connectivity to remote console services, such as SSH, reduces a server's exposure to risk.",
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
	"tags": ["terraform", "gcp", "compute", "firewall", "ssh"],
}

findings contains finding if {
	some r in tf.resources("google_compute_firewall")
	_allows_world_on_port(r.block, "22")
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("google_compute_firewall %q permits ingress from 0.0.0.0/0 to port 22.", [r.name]),
		"artifact_uri": r.path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": 1,
		"snippet": sprintf("%s.%s", [r.type, r.name]),
	}
}

_allows_world_on_port(block, port) if {
	not regex.match(`(?m)^\s*direction\s*=\s*"EGRESS"`, block)
	some cidrs in tf.string_list_attr(block, "source_ranges")
	cidrs == "0.0.0.0/0"
	some allow in tf.sub_blocks(block, "allow")
	_port_matches(allow, port)
}

_port_matches(allow, port) if {
	proto := tf.string_attr(allow, "protocol")
	proto != "icmp"
	ports := tf.string_list_attr(allow, "ports")
	count(ports) == 0
}

_port_matches(allow, port) if {
	proto := tf.string_attr(allow, "protocol")
	proto != "icmp"
	some p in tf.string_list_attr(allow, "ports")
	_port_in_range(p, port)
}

_port_in_range(spec, port) if spec == port

_port_in_range(spec, port) if {
	parts := split(spec, "-")
	count(parts) == 2
	lo := to_number(parts[0])
	hi := to_number(parts[1])
	pn := to_number(port)
	pn >= lo
	pn <= hi
}
