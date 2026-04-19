# Adapted from https://github.com/fugue/regula (FG_R00318).
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.fugue_arm_postgresql_log_connections

import rego.v1

import data.vulnetix.fugue.arm

metadata := {
	"id": "FUGUE-ARM-PG-04",
	"name": "PostgreSQL Database configuration 'log_connections' should be on",
	"description": "Enabling log_connections helps PostgreSQL Database to log attempted connection to the server, as well as successful completion of client authentication. Log data can be used to identify, troubleshoot, and repair configuration errors and suboptimal performance.",
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
	"tags": ["arm", "azure", "postgresql", "logging"],
}

_config_value(server, key) := v if {
	some cfg in arm.resources("Microsoft.DBforPostgreSQL/servers/configurations")
	cfg.path == server.path
	cfg.resource.name == sprintf("%s/%s", [server.resource.name, key])
	v := cfg.resource.properties.value
}

_ok(server) if {
	lower(_config_value(server, "log_connections")) == "on"
}

findings contains finding if {
	some s in arm.resources("Microsoft.DBforPostgreSQL/servers")
	not _ok(s)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("PostgreSQL server %q does not have log_connections=on.", [s.resource.name]),
		"artifact_uri": s.path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": 1,
		"snippet": sprintf("%s/%s", [s.resource.type, s.resource.name]),
	}
}
