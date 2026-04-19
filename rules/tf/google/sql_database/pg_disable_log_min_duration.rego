# Adapted from https://github.com/fugue/regula (FG_R00430).
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.fugue_tf_gcp_sql_pg_disable_log_min_duration

import rego.v1

import data.vulnetix.fugue.tf

metadata := {
	"id": "FUGUE-TF-GCP-SQL-05",
	"name": "PostgreSQL database instance 'log_min_duration_statement' database flag should be set to '-1' (disabled)",
	"description": "PostgreSQL database instance 'log_min_duration_statement' database flag should be set to '-1' (disabled). The PostgreSQL database instance flag 'log_min_duration_statement' defines the minimum amount of execution time of a SQL statement in milliseconds where the total duration of the statement is logged. Ensure this flag is disabled by setting it to -1. This means there will be no logging of SQL statements because some may include sensitive information that should be not be recorded in logs.",
	"help_uri": "https://github.com/fugue/regula",
	"languages": ["terraform", "hcl"],
	"severity": "medium",
	"level": "warning",
	"kind": "iac",
	"cwe": ["CWE-532"],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["terraform", "gcp", "sql", "postgres", "logging"],
}

findings contains finding if {
	some r in tf.resources("google_sql_database_instance")
	_is_postgres(r.block)
	not _flag_equals(r.block, "log_min_duration_statement", "-1")
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("google_sql_database_instance %q (PostgreSQL) does not set log_min_duration_statement = \"-1\".", [r.name]),
		"artifact_uri": r.path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": 1,
		"snippet": sprintf("%s.%s", [r.type, r.name]),
	}
}

_is_postgres(block) if {
	v := tf.string_attr(block, "database_version")
	startswith(upper(v), "POSTGRES")
}

_flag_equals(block, flag_name, want) if {
	some settings in tf.sub_blocks(block, "settings")
	some df in tf.sub_blocks(settings, "database_flags")
	tf.string_attr(df, "name") == flag_name
	tf.string_attr(df, "value") == want
}
