# Adapted from https://github.com/fugue/regula (FG_R00275).
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.fugue_tf_aws_s3_11

import rego.v1

import data.vulnetix.fugue.tf

metadata := {
	"id": "FUGUE-TF-AWS-S3-11",
	"name": "S3 bucket replication should be enabled",
	"description": "S3 replication can help with compliance, minimize latency, and aggregate logs while respecting data sovereignty laws.",
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
	"tags": ["terraform", "aws", "s3", "replication"],
}

findings contains finding if {
	some b in tf.resources("aws_s3_bucket")
	not tf.has_sub_block(b.block, "replication_configuration")
	not _has_replication_resource(b.name)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("aws_s3_bucket %q has no replication_configuration and no matching aws_s3_bucket_replication_configuration.", [b.name]),
		"artifact_uri": b.path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": 1,
		"snippet": sprintf("%s.%s", [b.type, b.name]),
	}
}

_has_replication_resource(name) if {
	some r in tf.resources("aws_s3_bucket_replication_configuration")
	tf.references(r.block, "aws_s3_bucket", name)
}
