# Adapted from https://github.com/fugue/regula (FG_R00428).
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.fugue_tf_gcp_sql_pg_enable_log_min_messages

import rego.v1

import data.vulnetix.fugue.tf

metadata := {
	"id": "FUGUE-TF-GCP-SQL-10",
	"name": "PostgreSQL database instance 'log_min_error_statement' database flag should be set appropriately",
	"description": "PostgreSQL database instance 'log_min_error_statement' database flag should be set appropriately. The PostgreSQL database instance flag 'log_min_messages' controls which message levels are written to the server log. Valid values include INFO, WARNING, and ERROR. Each level includes all the levels that follow it. The default is WARNING. If this flag is not set to the correct value, important messages useful for troubleshooting may not be logged.",
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
	"tags": ["terraform", "gcp", "sql", "postgres", "logging"],
}

findings contains finding if {
	some r in tf.resources("google_sql_database_instance")
	_is_postgres(r.block)
	_log_min_is_panic(r.block)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("google_sql_database_instance %q (PostgreSQL) sets log_min_messages = \"panic\".", [r.name]),
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

_log_min_is_panic(block) if {
	some settings in tf.sub_blocks(block, "settings")
	some df in tf.sub_blocks(settings, "database_flags")
	tf.string_attr(df, "name") == "log_min_messages"
	tf.string_attr(df, "value") == "panic"
}
