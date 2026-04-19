# Adapted from https://github.com/fugue/regula (FG_R00337).
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.fugue_tf_az_pg_log_retention_days

import rego.v1

import data.vulnetix.fugue.tf

metadata := {
	"id": "FUGUE-TF-AZ-PG-06",
	"name": "PostgreSQL Database configuration 'log_retention_days' should be greater than 3",
	"description": "PostgreSQL Database configuration 'log_retention days' should be greater than 3. Enabling log_retention_days helps PostgreSQL Database set the number of days a log file is retained.",
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
	"tags": ["terraform", "azure", "postgresql", "logging"],
}

findings contains finding if {
	some s in tf.resources("azurerm_postgresql_server")
	not _valid_retention(s.name)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("PostgreSQL server %q has log_retention_days <= 3.", [s.name]),
		"artifact_uri": s.path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": 1,
		"snippet": sprintf("%s.%s", [s.type, s.name]),
	}
}

# Default is 7, so absence is valid.
_valid_retention(server_name) if not _config_value(server_name, "log_retention_days")

_valid_retention(server_name) if {
	v := _config_value(server_name, "log_retention_days")
	to_number(v) > 3
}

_config_value(server_name, key) := v if {
	some c in tf.resources("azurerm_postgresql_configuration")
	tf.references(c.block, "azurerm_postgresql_server", server_name)
	tf.string_attr(c.block, "name") == key
	v := tf.string_attr(c.block, "value")
}
