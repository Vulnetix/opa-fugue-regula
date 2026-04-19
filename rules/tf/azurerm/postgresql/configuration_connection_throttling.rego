# Adapted from https://github.com/fugue/regula (FG_R00335).
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.fugue_tf_az_pg_connection_throttling

import rego.v1

import data.vulnetix.fugue.tf

metadata := {
	"id": "FUGUE-TF-AZ-PG-01",
	"name": "PostgreSQL Database configuration 'connection_throttling' should be on",
	"description": "PostgreSQL Database configuration 'connection_throttling' should be on. Enabling connection_throttling helps the PostgreSQL Database to set the verbosity of logged messages which in turn generates query and error logs with respect to concurrent connections.",
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
	not _valid_config(s.name, "connection_throttling")
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("PostgreSQL server %q has connection_throttling explicitly set to 'off'.", [s.name]),
		"artifact_uri": s.path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": 1,
		"snippet": sprintf("%s.%s", [s.type, s.name]),
	}
}

# Valid if no configuration is set (default is on) or if it's set to "on".
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
