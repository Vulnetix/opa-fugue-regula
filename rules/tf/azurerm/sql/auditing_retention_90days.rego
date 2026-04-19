# Adapted from https://github.com/fugue/regula (FG_R00283).
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.fugue_tf_az_sql_auditing_retention_90

import rego.v1

import data.vulnetix.fugue.tf

metadata := {
	"id": "FUGUE-TF-AZ-SQL-02",
	"name": "SQL Server auditing retention should be 90 days or greater",
	"description": "SQL Server auditing retention should be 90 days or greater. Audit logs can be used to check for anomalies and give insight into suspected breaches or misuse of information and access.",
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
	"tags": ["terraform", "azure", "sql", "auditing", "retention"],
}

findings contains finding if {
	some s in tf.resources("azurerm_sql_server")
	not _valid_auditing(s.block)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("SQL Server %q does not retain extended_auditing_policy for 90+ days.", [s.name]),
		"artifact_uri": s.path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": 1,
		"snippet": sprintf("%s.%s", [s.type, s.name]),
	}
}

findings contains finding if {
	some db in tf.resources("azurerm_sql_database")
	not _valid_auditing(db.block)
	not _server_valid_auditing_for(db.block)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("SQL Database %q and its parent server do not retain extended_auditing_policy for 90+ days.", [db.name]),
		"artifact_uri": db.path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": 1,
		"snippet": sprintf("%s.%s", [db.type, db.name]),
	}
}

_valid_auditing(block) if {
	some p in tf.sub_blocks(block, "extended_auditing_policy")
	tf.number_attr(p, "retention_in_days") >= 90
}

_valid_auditing(block) if {
	some p in tf.sub_blocks(block, "extended_auditing_policy")
	v := tf.string_attr(p, "retention_in_days")
	to_number(v) >= 90
}

_server_valid_auditing_for(db_block) if {
	some s in tf.resources("azurerm_sql_server")
	tf.references(db_block, "azurerm_sql_server", s.name)
	_valid_auditing(s.block)
}
