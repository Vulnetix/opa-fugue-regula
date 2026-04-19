# Adapted from https://github.com/fugue/regula (FG_R00099).
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.fugue_cfn_s3_encryption

import rego.v1

import data.vulnetix.fugue.cfn

metadata := {
	"id": "FUGUE-CFN-S3-04",
	"name": "S3 bucket server side encryption should be enabled",
	"description": "S3 bucket server side encryption should be enabled. SSE on S3 buckets at the object level protects data at rest and helps prevent the breach of sensitive information assets (SSE-S3, SSE-KMS, or SSE-C).",
	"help_uri": "https://github.com/fugue/regula",
	"languages": ["yaml", "json"],
	"severity": "high",
	"level": "error",
	"kind": "iac",
	"cwe": ["CWE-311"],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["cloudformation", "aws", "s3", "encryption"],
}

_has_sse(props) if {
	some cfg in props.BucketEncryption.ServerSideEncryptionConfiguration
	alg := cfg.ServerSideEncryptionByDefault.SSEAlgorithm
	alg != ""
	alg != null
}

findings contains finding if {
	some r in cfn.resources("AWS::S3::Bucket")
	props := cfn.properties(r)
	not _has_sse(props)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("S3 Bucket %q does not have BucketEncryption configured with an SSEAlgorithm.", [r.logical_id]),
		"artifact_uri": r.path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": 1,
		"snippet": sprintf("AWS::S3::Bucket/%s", [r.logical_id]),
	}
}
