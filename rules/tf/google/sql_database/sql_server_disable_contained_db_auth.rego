# Adapted from https://github.com/fugue/regula (FG_R00432).
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.fugue_tf_gcp_sql_sqlserver_disable_contained_db_auth

import rego.v1

import data.vulnetix.fugue.tf

metadata := {
	"id": "FUGUE-TF-GCP-SQL-13",
	"name": "SQL Server database instance 'contained database authentication' database flag should be set to 'off'",
	"description": "SQL Server database instance 'contained database authentication' database flag should be set to 'off'. The SQL Server database instance flag 'contained database authentication' controls whether a database is contained. Users can connect to a contained database without authenticating at the Database Engine level. Contained databases have some unique security threats mostly related with the USER WITH PASSWORD authentication process, which moves the authentication boundary from the Database Engine level to the database level. For this reason this flag should be set to off.",
	"help_uri": "https://github.com/fugue/regula",
	"languages": ["terraform", "hcl"],
	"severity": "medium",
	"level": "warning",
	"kind": "iac",
	"cwe": ["CWE-287"],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["terraform", "gcp", "sql", "sqlserver"],
}

findings contains finding if {
	some r in tf.resources("google_sql_database_instance")
	_is_sqlserver(r.block)
	not _flag_equals(r.block, "contained database authentication", "off")
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("google_sql_database_instance %q (SQL Server) does not set contained database authentication = \"off\".", [r.name]),
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
