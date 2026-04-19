# Adapted from https://github.com/fugue/regula (FG_R00229).
# Ported to the Vulnetix Rego input schema (input.file_contents).
# Simplified: flags aws_s3_bucket lacking a matching aws_s3_bucket_public_access_block or account-wide block with all four flags true.

package vulnetix.rules.fugue_tf_aws_s3_01

import rego.v1

import data.vulnetix.fugue.tf

metadata := {
	"id": "FUGUE-TF-AWS-S3-01",
	"name": "S3 buckets should have all 'block public access' options enabled",
	"description": "All four S3 Block Public Access settings (BlockPublicAcls, IgnorePublicAcls, BlockPublicPolicy, RestrictPublicBuckets) should be enabled.",
	"help_uri": "https://github.com/fugue/regula",
	"languages": ["terraform", "hcl"],
	"severity": "high",
	"level": "error",
	"kind": "iac",
	"cwe": ["CWE-284"],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["terraform", "aws", "s3", "public"],
}

findings contains finding if {
	some b in tf.resources("aws_s3_bucket")
	not _account_fully_blocked
	not _bucket_fully_blocked(b.name)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("aws_s3_bucket %q has no matching aws_s3_bucket_public_access_block with all four options enabled.", [b.name]),
		"artifact_uri": b.path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": 1,
		"snippet": sprintf("%s.%s", [b.type, b.name]),
	}
}

_account_fully_blocked if {
	some a in tf.resources("aws_s3_account_public_access_block")
	tf.bool_attr(a.block, "block_public_acls") == true
	tf.bool_attr(a.block, "ignore_public_acls") == true
	tf.bool_attr(a.block, "block_public_policy") == true
	tf.bool_attr(a.block, "restrict_public_buckets") == true
}

_bucket_fully_blocked(name) if {
	some b in tf.resources("aws_s3_bucket_public_access_block")
	tf.references(b.block, "aws_s3_bucket", name)
	tf.bool_attr(b.block, "block_public_acls") == true
	tf.bool_attr(b.block, "ignore_public_acls") == true
	tf.bool_attr(b.block, "block_public_policy") == true
	tf.bool_attr(b.block, "restrict_public_buckets") == true
}
