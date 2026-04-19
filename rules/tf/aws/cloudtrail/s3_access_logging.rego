# Adapted from https://github.com/fugue/regula (FG_R00031).
# Ported to the Vulnetix Rego input schema (input.file_contents).
# Simplified: only checks that the target S3 bucket (by Terraform resource name) has a logging sub-block.

package vulnetix.rules.fugue_tf_aws_ct_05

import rego.v1

import data.vulnetix.fugue.tf

metadata := {
	"id": "FUGUE-TF-AWS-CT-05",
	"name": "CloudTrail target S3 bucket should have access logging enabled",
	"description": "S3 bucket access logging should be enabled on S3 buckets that store CloudTrail log files to track access requests for security and incident response.",
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
	"tags": ["terraform", "aws", "cloudtrail", "s3", "logging"],
}

findings contains finding if {
	some r in tf.resources("aws_cloudtrail")
	# Match s3_bucket_name = aws_s3_bucket.<name>.id|bucket reference
	matches := regex.find_all_string_submatch_n(`s3_bucket_name\s*=\s*aws_s3_bucket\.([A-Za-z_][A-Za-z0-9_]*)\b`, r.block, -1)
	count(matches) > 0
	some m in matches
	bucket_name := m[1]
	not _bucket_has_logging(bucket_name)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("CloudTrail %q target bucket %q has no logging sub-block.", [r.name, bucket_name]),
		"artifact_uri": r.path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": 1,
		"snippet": sprintf("%s.%s", [r.type, r.name]),
	}
}

_bucket_has_logging(bucket_name) if {
	some b in tf.resources("aws_s3_bucket")
	b.name == bucket_name
	tf.has_sub_block(b.block, "logging")
}

_bucket_has_logging(bucket_name) if {
	some lc in tf.resources("aws_s3_bucket_logging")
	regex.match(sprintf(`bucket\s*=\s*aws_s3_bucket\.%s\b`, [bucket_name]), lc.block)
}
