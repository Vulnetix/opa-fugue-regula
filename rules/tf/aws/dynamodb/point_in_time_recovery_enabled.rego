# Adapted from https://github.com/fugue/regula (FG_R00106).
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.fugue_tf_aws_ddb_02

import rego.v1

import data.vulnetix.fugue.tf

metadata := {
	"id": "FUGUE-TF-AWS-DDB-02",
	"name": "DynamoDB tables should enable Point in Time Recovery",
	"description": "Point in Time Recovery should be enabled on DynamoDB tables to allow automatic backups and reduce the risk of data loss.",
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
	"tags": ["terraform", "aws", "dynamodb", "backup"],
}

findings contains finding if {
	some r in tf.resources("aws_dynamodb_table")
	not _pitr_enabled(r.block)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("DynamoDB table %q does not enable point_in_time_recovery.", [r.name]),
		"artifact_uri": r.path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": 1,
		"snippet": sprintf("%s.%s", [r.type, r.name]),
	}
}

_pitr_enabled(block) if {
	some pitr in tf.sub_blocks(block, "point_in_time_recovery")
	tf.bool_attr(pitr, "enabled") == true
}
