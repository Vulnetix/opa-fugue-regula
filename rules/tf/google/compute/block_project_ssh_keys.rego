# Adapted from https://github.com/fugue/regula (FG_R00413).
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.fugue_tf_gcp_gce_block_project_ssh_keys

import rego.v1

import data.vulnetix.fugue.tf

metadata := {
	"id": "FUGUE-TF-GCP-GCE-01",
	"name": "Compute instance 'block-project-ssh-keys' should be enabled",
	"description": "Compute instance 'block-project-ssh-keys' should be enabled. Project-wide SSH keys for Compute Engine instances may be easier to manage than instance-specific SSH keys, but if compromised, present increase security risk to all instances within a given project. Given this, using instance-specific SSH keys is the more secure approach. Please note that if OS Login is enabled, SSH keys in instance metadata are ignored, so blocking project-wide SSH keys is not necessary.",
	"help_uri": "https://github.com/fugue/regula",
	"languages": ["terraform", "hcl"],
	"severity": "medium",
	"level": "warning",
	"kind": "iac",
	"cwe": ["CWE-269"],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["terraform", "gcp", "compute", "ssh"],
}

findings contains finding if {
	some r in tf.resources("google_compute_instance")
	not _metadata_true(r.block, "enable-oslogin")
	not _metadata_true(r.block, "block-project-ssh-keys")
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("google_compute_instance %q does not enable 'block-project-ssh-keys' or OS Login.", [r.name]),
		"artifact_uri": r.path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": 1,
		"snippet": sprintf("%s.%s", [r.type, r.name]),
	}
}

_metadata_true(block, key) if {
	some meta in tf.sub_blocks(block, "metadata")
	regex.match(sprintf(`(?m)^\s*"?%s"?\s*=\s*"?true"?\b`, [key]), meta)
}
