# Adapted from https://github.com/fugue/regula (FG_R00227).
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.fugue_arm_key_vault_recoverable

import rego.v1

import data.vulnetix.fugue.arm

metadata := {
	"id": "FUGUE-ARM-KV-01",
	"name": "Key Vault 'Enable Soft Delete' and 'Enable Purge Protection' should be enabled",
	"description": "Enabling soft deletion ensures that even if the key vault is deleted, the key vault and its objects remain recoverable for next 90 days. In this span of 90 days, the key vault and its objects can be recovered or purged (permanent deletion). Enabling purge protection ensures that the key vault and its objects cannot be purged during the 90 day retention period.",
	"help_uri": "https://github.com/fugue/regula",
	"languages": ["json"],
	"severity": "medium",
	"level": "warning",
	"kind": "iac",
	"cwe": ["CWE-212"],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["arm", "azure", "key-vault"],
}

_ok(r) if {
	r.resource.properties.enablePurgeProtection == true
	r.resource.properties.enableSoftDelete == true
}

findings contains finding if {
	some r in arm.resources("Microsoft.KeyVault/vaults")
	not _ok(r)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Key Vault %q does not have both soft delete and purge protection enabled.", [r.resource.name]),
		"artifact_uri": r.path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": 1,
		"snippet": sprintf("%s/%s", [r.resource.type, r.resource.name]),
	}
}
