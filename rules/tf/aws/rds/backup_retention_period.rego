# Adapted from https://github.com/fugue/regula (FG_R00107).
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.fugue_tf_aws_rds_01

import rego.v1

import data.vulnetix.fugue.tf

metadata := {
	"id": "FUGUE-TF-AWS-RDS-01",
	"name": "RDS instances should have backup retention periods configured",
	"description": "Retention periods for RDS backups should be configured according to business and regulatory needs so that data can be recovered when needed but is not retained longer than necessary.",
	"help_uri": "https://github.com/fugue/regula",
	"languages": ["terraform", "hcl"],
	"severity": "medium",
	"level": "warning",
	"kind": "iac",
	"cwe": ["CWE-693"],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["terraform", "aws", "rds", "backup"],
}

findings contains finding if {
	some ty in {"aws_db_instance", "aws_rds_cluster"}
	some r in tf.resources(ty)
	_missing_retention(r.block)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("%s.%s does not have backup_retention_period > 0.", [r.type, r.name]),
		"artifact_uri": r.path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": 1,
		"snippet": sprintf("%s.%s", [r.type, r.name]),
	}
}

_missing_retention(block) if not tf.has_key(block, "backup_retention_period")

_missing_retention(block) if tf.number_attr(block, "backup_retention_period") == 0
