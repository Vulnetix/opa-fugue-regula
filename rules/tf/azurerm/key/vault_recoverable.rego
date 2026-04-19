# Adapted from https://github.com/fugue/regula (FG_R00227).
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.fugue_tf_az_kv_recoverable

import rego.v1

import data.vulnetix.fugue.tf

metadata := {
	"id": "FUGUE-TF-AZ-KV-01",
	"name": "Key Vault 'Enable Soft Delete' and 'Enable Purge Protection' should be enabled",
	"description": "Key Vault 'Enable Soft Delete' and 'Enable Purge Protection' should be enabled. Enabling soft deletion ensures that even if the key vault is deleted, the key vault and its objects remain recoverable for next 90 days. In this span of 90 days, the key vault and its objects can be recovered or purged (permanent deletion). Enabling purge protection ensures that the key vault and its objects cannot be purged during the 90 day retention period.",
	"help_uri": "https://github.com/fugue/regula",
	"languages": ["terraform", "hcl"],
	"severity": "medium",
	"level": "warning",
	"kind": "iac",
	"cwe": ["CWE-212"],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["terraform", "azure", "key-vault", "recovery"],
}

findings contains finding if {
	some r in tf.resources("azurerm_key_vault")
	not _recoverable(r.block)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Key Vault %q does not enable purge protection and soft delete.", [r.name]),
		"artifact_uri": r.path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": 1,
		"snippet": sprintf("%s.%s", [r.type, r.name]),
	}
}

_recoverable(block) if {
	tf.bool_attr(block, "purge_protection_enabled") == true
	tf.bool_attr(block, "soft_delete_enabled") == true
}
