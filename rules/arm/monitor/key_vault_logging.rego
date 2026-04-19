# Adapted from https://github.com/fugue/regula (FG_R00344).
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.fugue_arm_monitor_key_vault_logging

import rego.v1

import data.vulnetix.fugue.arm

metadata := {
	"id": "FUGUE-ARM-MON-01",
	"name": "Key Vault logging should be enabled",
	"description": "Enable AuditEvent logging for key vault instances to ensure interactions with key vaults are logged and available.",
	"help_uri": "https://github.com/fugue/regula",
	"languages": ["json"],
	"severity": "medium",
	"level": "warning",
	"kind": "iac",
	"cwe": ["CWE-778"],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["arm", "azure", "key-vault", "logging"],
}

_tokenize(str) := [p |
	some p in regex.split(`[\[\]()',\s]+`, str)
	p != ""
]

_retention_valid(ret) if {
	ret.enabled == true
	ret.days >= 180
}

_retention_valid(ret) if {
	ret.enabled == true
	ret.days == 0
}

_diag_is_valid_for_vault(ds, vault_name) if {
	scope := object.get(ds.properties, "scope", "")
	contains(lower(scope), "microsoft.keyvault/vaults")
	lower(vault_name) in _tokenize(lower(scope))
	some log in ds.properties.logs
	lower(log.category) == "auditevent"
	log.enabled == true
	_retention_valid(log.retentionPolicy)
}

_has_audit_logging(vault_name) if {
	some ds in arm.resources("Microsoft.Insights/diagnosticSettings")
	_diag_is_valid_for_vault(ds.resource, vault_name)
}

findings contains finding if {
	some kv in arm.resources("Microsoft.KeyVault/vaults")
	not _has_audit_logging(kv.resource.name)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Key Vault %q does not have AuditEvent diagnostic logging enabled.", [kv.resource.name]),
		"artifact_uri": kv.path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": 1,
		"snippet": sprintf("%s/%s", [kv.resource.type, kv.resource.name]),
	}
}
