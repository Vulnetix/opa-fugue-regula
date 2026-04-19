# Adapted from https://github.com/fugue/regula (FG_R00344).
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.fugue_tf_az_mon_kv_logging

import rego.v1

import data.vulnetix.fugue.tf

metadata := {
	"id": "FUGUE-TF-AZ-MON-01",
	"name": "Key Vault logging should be enabled",
	"description": "Key Vault logging should be enabled. Enable AuditEvent logging for key vault instances to ensure interactions with key vaults are logged and available.",
	"help_uri": "https://github.com/fugue/regula",
	"languages": ["terraform", "hcl"],
	"severity": "medium",
	"level": "warning",
	"kind": "iac",
	"cwe": ["CWE-778"],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["terraform", "azure", "monitor", "key-vault", "logging"],
}

findings contains finding if {
	some kv in tf.resources("azurerm_key_vault")
	not _has_audit_logging(kv.name)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Key Vault %q has no azurerm_monitor_diagnostic_setting with AuditEvent log enabled.", [kv.name]),
		"artifact_uri": kv.path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": 1,
		"snippet": sprintf("%s.%s", [kv.type, kv.name]),
	}
}

_has_audit_logging(vault_name) if {
	some ds in tf.resources("azurerm_monitor_diagnostic_setting")
	tf.references(ds.block, "azurerm_key_vault", vault_name)
	some log in tf.sub_blocks(ds.block, "log")
	cat := tf.string_attr(log, "category")
	lower(cat) == "auditevent"
	not tf.bool_attr(log, "enabled") == false
	_check_log_target(ds.block, log)
}

# Log Analytics and EventHub don't require retention checks.
_check_log_target(ds_block, _) if tf.has_key(ds_block, "log_analytics_workspace_id")

_check_log_target(ds_block, _) if tf.has_key(ds_block, "eventhub_authorization_rule_id")

# Storage account target requires valid retention.
_check_log_target(ds_block, log) if {
	tf.has_key(ds_block, "storage_account_id")
	some rp in tf.sub_blocks(log, "retention_policy")
	_check_retention(rp)
}

_check_retention(rp) if tf.bool_attr(rp, "enabled") == false

_check_retention(rp) if {
	tf.bool_attr(rp, "enabled") == true
	tf.number_attr(rp, "days") >= 180
}

_check_retention(rp) if {
	tf.bool_attr(rp, "enabled") == true
	tf.number_attr(rp, "days") == 0
}
