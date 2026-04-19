# Adapted from https://github.com/fugue/regula (FG_R00100).
# Ported to the Vulnetix Rego input schema (input.file_contents).
# Simplified: flags aws_s3_bucket missing a bucket_policy with Deny+aws:SecureTransport=false statement.

package vulnetix.rules.fugue_tf_aws_s3_10

import rego.v1

import data.vulnetix.fugue.tf

metadata := {
	"id": "FUGUE-TF-AWS-S3-10",
	"name": "S3 bucket policies should only allow requests that use HTTPS",
	"description": "Bucket policies should deny all HTTP requests and allow only HTTPS to protect data in transit.",
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
	"tags": ["terraform", "aws", "s3", "tls"],
}

findings contains finding if {
	some b in tf.resources("aws_s3_bucket")
	not _has_https_deny(b.name)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("aws_s3_bucket %q has no bucket policy denying aws:SecureTransport=false.", [b.name]),
		"artifact_uri": b.path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": 1,
		"snippet": sprintf("%s.%s", [b.type, b.name]),
	}
}

_has_https_deny(name) if {
	some p in tf.resources("aws_s3_bucket_policy")
	tf.references(p.block, "aws_s3_bucket", name)
	_secure_transport_deny(p.block)
}

_secure_transport_deny(block) if {
	regex.match(`(?s)"Effect"\s*:\s*"Deny"[\s\S]*?"aws:SecureTransport"[\s\S]*?"false"`, block)
}

_secure_transport_deny(block) if {
	regex.match(`(?s)"aws:SecureTransport"[\s\S]*?"false"[\s\S]*?"Effect"\s*:\s*"Deny"`, block)
}
