# Adapted from https://github.com/fugue/regula (FG_R00431).
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.fugue_tf_gcp_sql_sqlserver_disable_cross_db_ownership

import rego.v1

import data.vulnetix.fugue.tf

metadata := {
	"id": "FUGUE-TF-GCP-SQL-14",
	"name": "SQL Server database instance 'cross db ownership chaining' database flag should be set to 'off'",
	"description": "SQL Server database instance 'cross db ownership chaining' database flag should be set to 'off'. The SQL Server database instance flag 'cross db ownership chaining' allows you to control cross-database ownership chaining at the database level or to allow cross-database ownership chaining for all databases. This flag should be set to off unless all of the databases hosted on this instance must participate in cross-database ownership chaining and you are aware of the security implications of doing this.",
	"help_uri": "https://github.com/fugue/regula",
	"languages": ["terraform", "hcl"],
	"severity": "medium",
	"level": "warning",
	"kind": "iac",
	"cwe": ["CWE-269"],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["terraform", "gcp", "sql", "sqlserver"],
}

findings contains finding if {
	some r in tf.resources("google_sql_database_instance")
	_is_sqlserver(r.block)
	not _flag_equals(r.block, "cross db ownership chaining", "off")
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("google_sql_database_instance %q (SQL Server) does not set cross db ownership chaining = \"off\".", [r.name]),
		"artifact_uri": r.path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": 1,
		"snippet": sprintf("%s.%s", [r.type, r.name]),
	}
}

_is_sqlserver(block) if {
	v := tf.string_attr(block, "database_version")
	startswith(upper(v), "SQLSERVER")
}

_flag_equals(block, flag_name, want) if {
	some settings in tf.sub_blocks(block, "settings")
	some df in tf.sub_blocks(settings, "database_flags")
	tf.string_attr(df, "name") == flag_name
	tf.string_attr(df, "value") == want
}
