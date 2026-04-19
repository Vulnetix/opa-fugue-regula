# Adapted from https://github.com/fugue/regula (FG_R00451).
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.fugue_arm_key_vault_secret_expiry

import rego.v1

import data.vulnetix.fugue.arm

metadata := {
	"id": "FUGUE-ARM-KV-02",
	"name": "Key Vault secrets should have an expiration date set",
	"description": "By default, Key Vault secrets do not expire, which can be a security issue if secrets are compromised. As a best practice, an explicit expiration date should be set for secrets and secrets should be rotated.",
	"help_uri": "https://github.com/fugue/regula",
	"languages": ["json"],
	"severity": "medium",
	"level": "warning",
	"kind": "iac",
	"cwe": ["CWE-320"],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["arm", "azure", "key-vault", "secret-rotation"],
}

_has_expiry(r) if {
	exp := r.resource.properties.attributes.exp
	is_number(exp)
}

findings contains finding if {
	some r in arm.resources("Microsoft.KeyVault/vaults/secrets")
	not _has_expiry(r)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Key Vault secret %q does not have an expiration date.", [r.resource.name]),
		"artifact_uri": r.path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": 1,
		"snippet": sprintf("%s/%s", [r.resource.type, r.resource.name]),
	}
}
