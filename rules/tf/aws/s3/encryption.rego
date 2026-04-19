# Adapted from https://github.com/fugue/regula (FG_R00099).
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.fugue_tf_aws_s3_09

import rego.v1

import data.vulnetix.fugue.tf

metadata := {
	"id": "FUGUE-TF-AWS-S3-09",
	"name": "S3 bucket server-side encryption should be enabled",
	"description": "Enabling server-side encryption on S3 buckets protects data at rest and helps prevent the breach of sensitive data.",
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
	"tags": ["terraform", "aws", "s3", "encryption"],
}

findings contains finding if {
	some b in tf.resources("aws_s3_bucket")
	not tf.has_sub_block(b.block, "server_side_encryption_configuration")
	not _has_encryption_resource(b.name)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("aws_s3_bucket %q has no server_side_encryption_configuration and no matching aws_s3_bucket_server_side_encryption_configuration.", [b.name]),
		"artifact_uri": b.path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": 1,
		"snippet": sprintf("%s.%s", [b.type, b.name]),
	}
}

_has_encryption_resource(name) if {
	some r in tf.resources("aws_s3_bucket_server_side_encryption_configuration")
	tf.references(r.block, "aws_s3_bucket", name)
}
