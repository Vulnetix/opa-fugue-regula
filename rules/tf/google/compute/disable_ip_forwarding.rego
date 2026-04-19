# Adapted from https://github.com/fugue/regula (FG_R00416).
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.fugue_tf_gcp_gce_disable_ip_forwarding

import rego.v1

import data.vulnetix.fugue.tf

metadata := {
	"id": "FUGUE-TF-GCP-GCE-02",
	"name": "Compute instances 'IP forwarding' should not be enabled",
	"description": "Compute instances 'IP forwarding' should not be enabled. By default, a Compute Engine instance cannot forward a packet originated by another instance (\"IP forwarding\"). If this is enabled, Google Cloud no longer enforces packet source and destination checking, which can result in data loss or unintended information disclosure.",
	"help_uri": "https://github.com/fugue/regula",
	"languages": ["terraform", "hcl"],
	"severity": "low",
	"level": "note",
	"kind": "iac",
	"cwe": ["CWE-284"],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["terraform", "gcp", "compute", "networking"],
}

findings contains finding if {
	some r in tf.resources("google_compute_instance")
	tf.bool_attr(r.block, "can_ip_forward") == true
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("google_compute_instance %q has can_ip_forward = true.", [r.name]),
		"artifact_uri": r.path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": 1,
		"snippet": sprintf("%s.%s", [r.type, r.name]),
	}
}
