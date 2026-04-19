# Adapted from https://github.com/fugue/regula (FG_R00282).
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.fugue_tf_az_sql_auditing

import rego.v1

import data.vulnetix.fugue.tf

metadata := {
	"id": "FUGUE-TF-AZ-SQL-01",
	"name": "SQL Server auditing should be enabled",
	"description": "SQL Server auditing should be enabled. Enabling auditing at the server level ensures that all existing and newly created databases on the SQL server instance are audited.",
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
	"tags": ["terraform", "azure", "sql", "auditing"],
}

findings contains finding if {
	some s in tf.resources("azurerm_sql_server")
	not _has_auditing(s.block)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("SQL Server %q has no extended_auditing_policy block.", [s.name]),
		"artifact_uri": s.path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": 1,
		"snippet": sprintf("%s.%s", [s.type, s.name]),
	}
}

findings contains finding if {
	some db in tf.resources("azurerm_sql_database")
	not _has_auditing(db.block)
	not _server_has_auditing_for(db.block)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("SQL Database %q and its parent server have no extended_auditing_policy block.", [db.name]),
		"artifact_uri": db.path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": 1,
		"snippet": sprintf("%s.%s", [db.type, db.name]),
	}
}

_has_auditing(block) if tf.has_sub_block(block, "extended_auditing_policy")

_server_has_auditing_for(db_block) if {
	some s in tf.resources("azurerm_sql_server")
	tf.references(db_block, "azurerm_sql_server", s.name)
	_has_auditing(s.block)
}
