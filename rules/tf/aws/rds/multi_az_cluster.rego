# Adapted from https://github.com/fugue/regula (FG_R00209).
# Ported to the Vulnetix Rego input schema (input.file_contents).
# Simplified: flags aws_rds_cluster with fewer than 2 availability_zones listed.

package vulnetix.rules.fugue_tf_aws_rds_05

import rego.v1

import data.vulnetix.fugue.tf

metadata := {
	"id": "FUGUE-TF-AWS-RDS-05",
	"name": "RDS Aurora clusters should be multi-AZ",
	"description": "An Aurora cluster in a Multi-AZ deployment provides enhanced availability and durability of data by replicating to an Aurora replica in another availability zone.",
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
	"tags": ["terraform", "aws", "rds", "availability"],
}

findings contains finding if {
	some r in tf.resources("aws_rds_cluster")
	azs := tf.string_list_attr(r.block, "availability_zones")
	count(azs) < 2
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("aws_rds_cluster %q has fewer than 2 availability_zones configured.", [r.name]),
		"artifact_uri": r.path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": 1,
		"snippet": sprintf("%s.%s", [r.type, r.name]),
	}
}

findings contains finding if {
	some r in tf.resources("aws_rds_cluster")
	not tf.has_key(r.block, "availability_zones")
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("aws_rds_cluster %q does not declare availability_zones.", [r.name]),
		"artifact_uri": r.path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": 1,
		"snippet": sprintf("%s.%s", [r.type, r.name]),
	}
}
