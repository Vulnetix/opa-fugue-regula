# Adapted from https://github.com/fugue/regula (FG_R00417).
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.fugue_tf_gcp_gce_disk_encryption

import rego.v1

import data.vulnetix.fugue.tf

metadata := {
	"id": "FUGUE-TF-GCP-GCE-04",
	"name": "Compute instance disks should be encrypted with customer-supplied encryption keys (CSEKs)",
	"description": "Compute instance disks should be encrypted with customer-supplied encryption keys (CSEKs). Google Cloud encrypts all data at rest by default with Google-generated keys. However, for business critical instances, users may want to use customer-supplied encryption keys (CSEKs) for an additional layer of protection as data encrypted with CSEKs cannot be accessed by Google.",
	"help_uri": "https://github.com/fugue/regula",
	"languages": ["terraform", "hcl"],
	"severity": "medium",
	"level": "warning",
	"kind": "iac",
	"cwe": ["CWE-311"],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["terraform", "gcp", "compute", "encryption"],
}

findings contains finding if {
	some r in tf.resources("google_compute_instance")
	_has_unencrypted_disk(r.block)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("google_compute_instance %q has a boot/attached/scratch disk without a customer-supplied encryption key.", [r.name]),
		"artifact_uri": r.path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": 1,
		"snippet": sprintf("%s.%s", [r.type, r.name]),
	}
}

_has_unencrypted_disk(block) if {
	some disk in tf.sub_blocks(block, "boot_disk")
	not _disk_encrypted(disk)
}

_has_unencrypted_disk(block) if {
	some disk in tf.sub_blocks(block, "attached_disk")
	not _disk_encrypted(disk)
}

_has_unencrypted_disk(block) if {
	some disk in tf.sub_blocks(block, "scratch_disk")
	not _disk_encrypted(disk)
}

_disk_encrypted(disk) if regex.match(`disk_encryption_key_(sha256|raw)\s*=\s*"[^"]+"`, disk)

_disk_encrypted(disk) if tf.has_sub_block(disk, "disk_encryption_key")
