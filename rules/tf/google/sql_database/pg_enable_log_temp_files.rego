# Adapted from https://github.com/fugue/regula (FG_R00429).
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.fugue_tf_gcp_sql_pg_enable_log_temp_files

import rego.v1

import data.vulnetix.fugue.tf

metadata := {
	"id": "FUGUE-TF-GCP-SQL-11",
	"name": "PostgreSQL database instance 'log_temp_files' database flag should be set to '0' (on)",
	"description": "PostgreSQL database instance 'log_temp_files' database flag should be set to '0' (on). The PostgreSQL database instance flag 'log_temp_files' controls logging temporary files and their size when deleted. Setting this flag to 0 causes all temporary files to be logged. If any temporary files are not logged, it may be more difficult to identify potential performance issues due to either poor application coding or deliberate resource starvation attempts.",
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
	not _flag_equals(r.block, "log_temp_files", "0")
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("google_sql_database_instance %q (PostgreSQL) does not set log_temp_files = \"0\".", [r.name]),
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
