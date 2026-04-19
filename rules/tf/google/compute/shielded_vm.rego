# Adapted from https://github.com/fugue/regula (FG_R00418).
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.fugue_tf_gcp_gce_shielded_vm

import rego.v1

import data.vulnetix.fugue.tf

metadata := {
	"id": "FUGUE-TF-GCP-GCE-11",
	"name": "Compute instance Shielded VM should be enabled",
	"description": "Compute instance Shielded VM should be enabled. Compute Engine Shielded VM instances enables several security features to ensure that instances haven't been compromised by boot or kernel-level malware or rootkits. This is achieved through use of Secure Boot, vTPM-enabled Measured Boot, and integrity monitoring.",
	"help_uri": "https://github.com/fugue/regula",
	"languages": ["terraform", "hcl"],
	"severity": "medium",
	"level": "warning",
	"kind": "iac",
	"cwe": ["CWE-1283"],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["terraform", "gcp", "compute", "shielded-vm"],
}

findings contains finding if {
	some r in tf.resources("google_compute_instance")
	not _shielded_vm_ok(r.block)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("google_compute_instance %q is missing a shielded_instance_config with enable_secure_boot = true.", [r.name]),
		"artifact_uri": r.path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": 1,
		"snippet": sprintf("%s.%s", [r.type, r.name]),
	}
}

_shielded_vm_ok(block) if {
	some cfg in tf.sub_blocks(block, "shielded_instance_config")
	tf.bool_attr(cfg, "enable_secure_boot") == true
	tf.is_not_false(cfg, "enable_integrity_monitoring")
	tf.is_not_false(cfg, "enable_vtpm")
}
