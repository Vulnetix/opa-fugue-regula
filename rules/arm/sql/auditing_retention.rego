# Adapted from https://github.com/fugue/regula (FG_R00283).
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.fugue_arm_sql_auditing_retention

import rego.v1

import data.vulnetix.fugue.arm

metadata := {
	"id": "FUGUE-ARM-SQL-02",
	"name": "SQL Server auditing retention should be 90 days or greater",
	"description": "Audit Logs can be used to check for anomalies and give insight into suspected breaches or misuse of information and access.",
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
	"tags": ["arm", "azure", "sql", "auditing", "retention"],
}

_audit_settings_for(server) := [s.resource |
	some s in arm.resources("Microsoft.Sql/servers/auditingSettings")
	s.path == server.path
	startswith(s.resource.name, sprintf("%s/", [server.resource.name]))
]

_ok(server) if {
	some s in _audit_settings_for(server)
	s.properties.retentionDays >= 90
}

findings contains finding if {
	some srv in arm.resources("Microsoft.Sql/servers")
	not _ok(srv)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("SQL Server %q auditing retention is less than 90 days.", [srv.resource.name]),
		"artifact_uri": srv.path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": 1,
		"snippet": sprintf("%s/%s", [srv.resource.type, srv.resource.name]),
	}
}
