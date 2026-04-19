# Adapted from https://github.com/fugue/regula (FG_R00226).
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.fugue_arm_postgresql_enforce_ssl

import rego.v1

import data.vulnetix.fugue.arm

metadata := {
	"id": "FUGUE-ARM-PG-02",
	"name": "PostgreSQL Database server 'enforce SSL connection' should be enabled",
	"description": "Enforcing SSL connections between your database server and your client applications helps protect against \"man in the middle\" attacks by encrypting the data stream between the server and your application.",
	"help_uri": "https://github.com/fugue/regula",
	"languages": ["json"],
	"severity": "medium",
	"level": "warning",
	"kind": "iac",
	"cwe": ["CWE-319"],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["arm", "azure", "postgresql", "tls"],
}

_ok(r) if {
	lower(object.get(r.resource.properties, "sslEnforcement", "")) == "enabled"
}

findings contains finding if {
	some r in arm.resources("Microsoft.DBforPostgreSQL/servers")
	not _ok(r)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("PostgreSQL server %q does not enforce SSL.", [r.resource.name]),
		"artifact_uri": r.path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": 1,
		"snippet": sprintf("%s/%s", [r.resource.type, r.resource.name]),
	}
}
