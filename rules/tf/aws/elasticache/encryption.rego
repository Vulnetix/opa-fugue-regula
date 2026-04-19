# Adapted from https://github.com/fugue/regula (FG_R00105).
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.fugue_tf_aws_ec_01

import rego.v1

import data.vulnetix.fugue.tf

metadata := {
	"id": "FUGUE-TF-AWS-EC-01",
	"name": "ElastiCache transport encryption should be enabled",
	"description": "In-transit encryption should be enabled for ElastiCache replication groups to protect data moved between nodes, replication groups, and applications.",
	"help_uri": "https://github.com/fugue/regula",
	"languages": ["terraform", "hcl"],
	"severity": "medium",
	"level": "warning",
	"kind": "iac",
	"cwe": ["CWE-319"],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["terraform", "aws", "elasticache", "tls"],
}

findings contains finding if {
	some r in tf.resources("aws_elasticache_replication_group")
	tf.is_not_true(r.block, "transit_encryption_enabled")
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("ElastiCache replication group %q does not enable transit_encryption_enabled.", [r.name]),
		"artifact_uri": r.path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": 1,
		"snippet": sprintf("%s.%s", [r.type, r.name]),
	}
}
