# Adapted from https://github.com/fugue/regula (FG_R00280).
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.fugue_tf_aws_rds_02

import rego.v1

import data.vulnetix.fugue.tf

metadata := {
	"id": "FUGUE-TF-AWS-RDS-02",
	"name": "RDS instance deletion protection should be enabled",
	"description": "Enabling deletion protection ensures that a user cannot accidentally or intentionally delete the database.",
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
	"tags": ["terraform", "aws", "rds"],
}

findings contains finding if {
	some r in tf.resources("aws_db_instance")
	tf.is_not_true(r.block, "deletion_protection")
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("aws_db_instance %q does not have deletion_protection = true.", [r.name]),
		"artifact_uri": r.path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": 1,
		"snippet": sprintf("%s.%s", [r.type, r.name]),
	}
}
