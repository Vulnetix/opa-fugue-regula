# Adapted from https://github.com/fugue/regula (FG_R00415).
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.fugue_tf_gcp_gce_disable_serial_ports

import rego.v1

import data.vulnetix.fugue.tf

metadata := {
	"id": "FUGUE-TF-GCP-GCE-03",
	"name": "Compute instances 'Enable connecting to serial ports' should not be enabled",
	"description": "Compute instances 'Enable connecting to serial ports' should not be enabled. A Compute Engine instance's serial port - also known as an interactive serial console - does not support IP-based access restrictions. If enabled, the interactive serial console can be used by clients to connect to the instance from any IP address. This enables anyone who has the correct SSH key, username, and other login information to connect to the instance.",
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
	"tags": ["terraform", "gcp", "compute", "serial-port"],
}

findings contains finding if {
	some r in tf.resources("google_compute_instance")
	_serial_port_enabled(r.block)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("google_compute_instance %q enables serial-port-enable in metadata.", [r.name]),
		"artifact_uri": r.path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": 1,
		"snippet": sprintf("%s.%s", [r.type, r.name]),
	}
}

_serial_port_enabled(block) if {
	some meta in tf.sub_blocks(block, "metadata")
	regex.match(`(?m)^\s*"?serial-port-enable"?\s*=\s*"?true"?\b`, meta)
}
