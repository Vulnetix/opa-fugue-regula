# Adapted from https://github.com/fugue/regula (FG_R00436).
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.fugue_tf_gcp_sql_automated_backups

import rego.v1

import data.vulnetix.fugue.tf

metadata := {
	"id": "FUGUE-TF-GCP-SQL-01",
	"name": "SQL database instance automated backups should be enabled",
	"description": "SQL database instance automated backups should be enabled. SQL database instances should be configured to be automatically backed up. Backups enable a Cloud SQL instance to recover lost data or to recover from a problem with that instance.",
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
	"tags": ["terraform", "gcp", "sql", "backup"],
}

findings contains finding if {
	some r in tf.resources("google_sql_database_instance")
	not _backups_enabled(r.block)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("google_sql_database_instance %q does not enable automated backups.", [r.name]),
		"artifact_uri": r.path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": 1,
		"snippet": sprintf("%s.%s", [r.type, r.name]),
	}
}

_backups_enabled(block) if {
	some settings in tf.sub_blocks(block, "settings")
	some bc in tf.sub_blocks(settings, "backup_configuration")
	tf.bool_attr(bc, "enabled") == true
}
