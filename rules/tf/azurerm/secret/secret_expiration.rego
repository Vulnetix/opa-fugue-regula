# Adapted from https://github.com/fugue/regula (FG_R00451).
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.fugue_tf_az_kv_secret_expiration

import rego.v1

import data.vulnetix.fugue.tf

metadata := {
	"id": "FUGUE-TF-AZ-KV-02",
	"name": "Key Vault secrets should have an expiration date",
	"description": "Key Vault secrets should have an expiration date. By default, Key Vault secrets do not expire, which can be a security issue if secrets are compromised. As a best practice, an explicit expiration date should be set for secrets and secrets should be rotated.",
	"help_uri": "https://github.com/fugue/regula",
	"languages": ["terraform", "hcl"],
	"severity": "medium",
	"level": "warning",
	"kind": "iac",
	"cwe": ["CWE-522"],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["terraform", "azure", "key-vault", "secret"],
}

findings contains finding if {
	some s in tf.resources("azurerm_key_vault_secret")
	not _has_expiration(s.block)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Key Vault secret %q does not set an expiration_date.", [s.name]),
		"artifact_uri": s.path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": 1,
		"snippet": sprintf("%s.%s", [s.type, s.name]),
	}
}

_has_expiration(block) if {
	v := tf.string_attr(block, "expiration_date")
	count(v) > 0
}
