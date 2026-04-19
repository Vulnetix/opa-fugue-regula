# Adapted from https://github.com/fugue/regula (FG_R00101).
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.fugue_tf_aws_s3_12

import rego.v1

import data.vulnetix.fugue.tf

metadata := {
	"id": "FUGUE-TF-AWS-S3-12",
	"name": "S3 bucket versioning and lifecycle policies should be enabled",
	"description": "Enabling object versioning and lifecycle policies protects data availability and integrity.",
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
	"tags": ["terraform", "aws", "s3", "versioning"],
}

findings contains finding if {
	some b in tf.resources("aws_s3_bucket")
	not _has_versioning(b)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("aws_s3_bucket %q has no versioning enabled.", [b.name]),
		"artifact_uri": b.path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": 1,
		"snippet": sprintf("%s.%s", [b.type, b.name]),
	}
}

findings contains finding if {
	some b in tf.resources("aws_s3_bucket")
	not _has_lifecycle(b)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("aws_s3_bucket %q has no lifecycle rule configured.", [b.name]),
		"artifact_uri": b.path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": 1,
		"snippet": sprintf("%s.%s", [b.type, b.name]),
	}
}

_has_versioning(b) if {
	some sub in tf.sub_blocks(b.block, "versioning")
	tf.bool_attr(sub, "enabled") == true
}

_has_versioning(b) if {
	some v in tf.resources("aws_s3_bucket_versioning")
	tf.references(v.block, "aws_s3_bucket", b.name)
	some c in tf.sub_blocks(v.block, "versioning_configuration")
	lower(tf.string_attr(c, "status")) == "enabled"
}

_has_lifecycle(b) if tf.has_sub_block(b.block, "lifecycle_rule")

_has_lifecycle(b) if {
	some l in tf.resources("aws_s3_bucket_lifecycle_configuration")
	tf.references(l.block, "aws_s3_bucket", b.name)
	tf.has_sub_block(l.block, "rule")
}
