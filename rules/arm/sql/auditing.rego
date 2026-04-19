# Adapted from https://github.com/fugue/regula (FG_R00282).
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.fugue_arm_sql_auditing

import rego.v1

import data.vulnetix.fugue.arm

metadata := {
	"id": "FUGUE-ARM-SQL-01",
	"name": "SQL Server auditing should be enabled",
	"description": "The Azure platform allows a SQL server to be created as a service. Enabling auditing at the server level ensures that all existing and newly created databases on the SQL server instance are audited. Auditing policy applied on the SQL database does not override auditing policy and settings applied on the particular SQL server where the database is hosted.",
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
	"tags": ["arm", "azure", "sql", "auditing"],
}

_audit_settings_for(server) := [s.resource |
	some s in arm.resources("Microsoft.Sql/servers/auditingSettings")
	s.path == server.path
	startswith(s.resource.name, sprintf("%s/", [server.resource.name]))
]

_ok(server) if {
	some s in _audit_settings_for(server)
	lower(object.get(s.properties, "state", "")) == "enabled"
}

findings contains finding if {
	some srv in arm.resources("Microsoft.Sql/servers")
	not _ok(srv)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("SQL Server %q does not have auditing enabled.", [srv.resource.name]),
		"artifact_uri": srv.path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": 1,
		"snippet": sprintf("%s/%s", [srv.resource.type, srv.resource.name]),
	}
}
