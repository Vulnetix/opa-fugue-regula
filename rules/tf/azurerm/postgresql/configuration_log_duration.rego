# Adapted from https://github.com/fugue/regula (FG_R00333).
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.fugue_tf_az_pg_log_duration

import rego.v1

import data.vulnetix.fugue.tf

metadata := {
	"id": "FUGUE-TF-AZ-PG-05",
	"name": "PostgreSQL Database configuration 'log_duration' should be on",
	"description": "PostgreSQL Database configuration 'log_duration' should be on. Enabling log_duration helps the PostgreSQL Database log the duration of each completed SQL statement.",
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
	not _valid_config(s.name, "log_duration")
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("PostgreSQL server %q has log_duration explicitly set to 'off'.", [s.name]),
		"artifact_uri": s.path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": 1,
		"snippet": sprintf("%s.%s", [s.type, s.name]),
	}
}

_valid_config(server_name, key) if not _config_value(server_name, key)

_valid_config(server_name, key) if {
	v := _config_value(server_name, key)
	lower(v) == "on"
}

_config_value(server_name, key) := v if {
	some c in tf.resources("azurerm_postgresql_configuration")
	tf.references(c.block, "azurerm_postgresql_server", server_name)
	tf.string_attr(c.block, "name") == key
	v := tf.string_attr(c.block, "value")
}
