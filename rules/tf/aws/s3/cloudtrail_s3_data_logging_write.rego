# Adapted from https://github.com/fugue/regula (FG_R00354).
# Ported to the Vulnetix Rego input schema (input.file_contents).
# Simplified: flags aws_s3_bucket with no aws_cloudtrail event_selector logging S3 Object writes.

package vulnetix.rules.fugue_tf_aws_s3_08

import rego.v1

import data.vulnetix.fugue.tf

metadata := {
	"id": "FUGUE-TF-AWS-S3-08",
	"name": "S3 bucket object-level logging for write events should be enabled",
	"description": "Object-level S3 write events (PutObject, DeleteObject) are not logged by default; enable CloudTrail data events for sensitive buckets.",
	"help_uri": "https://github.com/fugue/regula",
	"languages": ["terraform", "hcl"],
	"severity": "low",
	"level": "note",
	"kind": "iac",
	"cwe": ["CWE-778"],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["terraform", "aws", "s3", "cloudtrail"],
}

findings contains finding if {
	some b in tf.resources("aws_s3_bucket")
	not _logged_write(b.name)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("aws_s3_bucket %q has no CloudTrail data event selector covering write events.", [b.name]),
		"artifact_uri": b.path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": 1,
		"snippet": sprintf("%s.%s", [b.type, b.name]),
	}
}

_logged_write(bucket_name) if {
	some t in tf.resources("aws_cloudtrail")
	some sel in tf.sub_blocks(t.block, "event_selector")
	_selector_write(sel)
	some dr in tf.sub_blocks(sel, "data_resource")
	tf.string_attr(dr, "type") == "AWS::S3::Object"
	_data_resource_matches(dr, bucket_name)
}

_selector_write(sel) if tf.string_attr(sel, "read_write_type") == "All"

_selector_write(sel) if tf.string_attr(sel, "read_write_type") == "WriteOnly"

_selector_write(sel) if not tf.has_key(sel, "read_write_type")

_data_resource_matches(dr, _) if {
	values := tf.string_list_attr(dr, "values")
	some v in values
	v == "arn:aws:s3:::"
}

_data_resource_matches(dr, bucket_name) if tf.references(dr, "aws_s3_bucket", bucket_name)
