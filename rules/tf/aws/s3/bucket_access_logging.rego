# Adapted from https://github.com/fugue/regula (FG_R00274).
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.fugue_tf_aws_s3_02

import rego.v1

import data.vulnetix.fugue.tf

metadata := {
	"id": "FUGUE-TF-AWS-S3-02",
	"name": "S3 bucket access logging should be enabled",
	"description": "Enabling server access logging provides detailed records for the requests that are made to an S3 bucket, which supports security and compliance auditing.",
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
	"tags": ["terraform", "aws", "s3", "logging"],
}

findings contains finding if {
	some b in tf.resources("aws_s3_bucket")
	not tf.has_sub_block(b.block, "logging")
	not _has_logging_resource(b.name)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("aws_s3_bucket %q has no logging block and no matching aws_s3_bucket_logging.", [b.name]),
		"artifact_uri": b.path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": 1,
		"snippet": sprintf("%s.%s", [b.type, b.name]),
	}
}

_has_logging_resource(name) if {
	some l in tf.resources("aws_s3_bucket_logging")
	tf.references(l.block, "aws_s3_bucket", name)
}
