# Adapted from https://github.com/fugue/regula (FG_R00279).
# Ported to the Vulnetix Rego input schema (input.file_contents).
# Simplified: flags aws_s3_bucket with acl = "public-read" or "public-read-write".

package vulnetix.rules.fugue_tf_aws_s3_03

import rego.v1

import data.vulnetix.fugue.tf

metadata := {
	"id": "FUGUE-TF-AWS-S3-03",
	"name": "S3 bucket ACLs should not be configured for public read access",
	"description": "A bucket with an ACL configured for public read access can potentially be made public, allowing any AWS user or anonymous user to access data in it.",
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

invalid_canned_acl := {"public-read", "public-read-write"}

findings contains finding if {
	some b in tf.resources("aws_s3_bucket")
	acl := tf.string_attr(b.block, "acl")
	invalid_canned_acl[acl]
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("aws_s3_bucket %q has acl = %q (allows public read).", [b.name, acl]),
		"artifact_uri": b.path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": 1,
		"snippet": sprintf("%s.%s", [b.type, b.name]),
	}
}

findings contains finding if {
	some a in tf.resources("aws_s3_bucket_acl")
	acl := tf.string_attr(a.block, "acl")
	invalid_canned_acl[acl]
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("aws_s3_bucket_acl %q sets acl = %q (allows public read).", [a.name, acl]),
		"artifact_uri": a.path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": 1,
		"snippet": sprintf("%s.%s", [a.type, a.name]),
	}
}
