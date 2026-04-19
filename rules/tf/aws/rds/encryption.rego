# Adapted from https://github.com/fugue/regula (FG_R00093).
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.fugue_tf_aws_rds_03

import rego.v1

import data.vulnetix.fugue.tf

metadata := {
	"id": "FUGUE-TF-AWS-RDS-03",
	"name": "RDS instances should be encrypted",
	"description": "Encrypting RDS DB instances provides an extra layer of security by protecting data from unauthorized access.",
	"help_uri": "https://github.com/fugue/regula",
	"languages": ["terraform", "hcl"],
	"severity": "high",
	"level": "error",
	"kind": "iac",
	"cwe": ["CWE-311"],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["terraform", "aws", "rds", "encryption"],
}

findings contains finding if {
	some ty in {"aws_db_instance", "aws_rds_cluster"}
	some r in tf.resources(ty)
	tf.is_not_true(r.block, "storage_encrypted")
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("%s.%s does not have storage_encrypted = true.", [r.type, r.name]),
		"artifact_uri": r.path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": 1,
		"snippet": sprintf("%s.%s", [r.type, r.name]),
	}
}
