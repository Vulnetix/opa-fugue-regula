# Adapted from https://github.com/fugue/regula (FG_R00423).
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.fugue_tf_gcp_sql_mysql_no_local_infile

import rego.v1

import data.vulnetix.fugue.tf

metadata := {
	"id": "FUGUE-TF-GCP-SQL-02",
	"name": "MySQL database instance 'local_infile' database flag should be set to 'off'",
	"description": "MySQL database instance 'local_infile' database flag should be set to 'off'. The MySQL database instance 'local_infile' flag controls server-side LOCAL capabilities for LOAD DATA statements. If permitted, clients can perform local data loading, which can be a security risk.",
	"help_uri": "https://github.com/fugue/regula",
	"languages": ["terraform", "hcl"],
	"severity": "medium",
	"level": "warning",
	"kind": "iac",
	"cwe": ["CWE-284"],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["terraform", "gcp", "sql", "mysql"],
}

findings contains finding if {
	some r in tf.resources("google_sql_database_instance")
	_is_mysql(r.block)
	not _flag_equals(r.block, "local_infile", "off")
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("google_sql_database_instance %q (MySQL) does not set database_flags.local_infile = \"off\".", [r.name]),
		"artifact_uri": r.path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": 1,
		"snippet": sprintf("%s.%s", [r.type, r.name]),
	}
}

_is_mysql(block) if {
	v := tf.string_attr(block, "database_version")
	startswith(upper(v), "MYSQL")
}

_flag_equals(block, flag_name, want) if {
	some settings in tf.sub_blocks(block, "settings")
	some df in tf.sub_blocks(settings, "database_flags")
	tf.string_attr(df, "name") == flag_name
	tf.string_attr(df, "value") == want
}
