# Adapted from https://github.com/fugue/regula (FG_R00335).
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.fugue_arm_postgresql_connection_throttling

import rego.v1

import data.vulnetix.fugue.arm

metadata := {
	"id": "FUGUE-ARM-PG-01",
	"name": "PostgreSQL Database configuration 'connection_throttling' should be on",
	"description": "Enabling connection_throttling helps the PostgreSQL Database to Set the verbosity of logged messages which in turn generates query and error logs with respect to concurrent connections, that could lead to a successful Denial of Service (DoS) attack by exhausting connection resources.",
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
	lower(_config_value(server, "connection_throttling")) == "on"
}

findings contains finding if {
	some s in arm.resources("Microsoft.DBforPostgreSQL/servers")
	not _ok(s)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("PostgreSQL server %q does not have connection_throttling=on.", [s.resource.name]),
		"artifact_uri": s.path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": 1,
		"snippet": sprintf("%s/%s", [s.resource.type, s.resource.name]),
	}
}
