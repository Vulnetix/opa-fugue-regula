# Adapted from https://github.com/fugue/regula (FG_R00277).
# Ported to the Vulnetix Rego input schema (input.file_contents).
# Simplified: flags public-read/public-read-write ACL or bucket_policy with Principal "*" Allow, unless restrict_public_buckets or ignore_public_acls is enabled.

package vulnetix.rules.fugue_tf_aws_s3_04

import rego.v1

import data.vulnetix.fugue.tf

metadata := {
	"id": "FUGUE-TF-AWS-S3-04",
	"name": "S3 buckets should not be publicly readable",
	"description": "A bucket with a public ACL or bucket policy is exposed to the internet if all block public access settings are disabled, posing a critical security risk.",
	"help_uri": "https://github.com/fugue/regula",
	"languages": ["terraform", "hcl"],
	"severity": "critical",
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
	not _account_restrict_public
	not _bucket_restrict_public(b.name)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("aws_s3_bucket %q has acl = %q and no ignore/restrict block.", [b.name, acl]),
		"artifact_uri": b.path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": 1,
		"snippet": sprintf("%s.%s", [b.type, b.name]),
	}
}

findings contains finding if {
	some p in tf.resources("aws_s3_bucket_policy")
	_wildcard_principal_allow(p.block)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("aws_s3_bucket_policy %q has an Allow statement with Principal=\"*\".", [p.name]),
		"artifact_uri": p.path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": 1,
		"snippet": sprintf("%s.%s", [p.type, p.name]),
	}
}

_account_restrict_public if {
	some a in tf.resources("aws_s3_account_public_access_block")
	tf.bool_attr(a.block, "restrict_public_buckets") == true
}

_account_restrict_public if {
	some a in tf.resources("aws_s3_account_public_access_block")
	tf.bool_attr(a.block, "ignore_public_acls") == true
}

_bucket_restrict_public(name) if {
	some b in tf.resources("aws_s3_bucket_public_access_block")
	tf.references(b.block, "aws_s3_bucket", name)
	tf.bool_attr(b.block, "restrict_public_buckets") == true
}

_bucket_restrict_public(name) if {
	some b in tf.resources("aws_s3_bucket_public_access_block")
	tf.references(b.block, "aws_s3_bucket", name)
	tf.bool_attr(b.block, "ignore_public_acls") == true
}

_wildcard_principal_allow(block) if {
	regex.match(`(?s)"Effect"\s*:\s*"Allow"[\s\S]*?"Principal"\s*:\s*"\*"`, block)
}

_wildcard_principal_allow(block) if {
	regex.match(`(?s)"Principal"\s*:\s*"\*"[\s\S]*?"Effect"\s*:\s*"Allow"`, block)
}

_wildcard_principal_allow(block) if {
	regex.match(`(?s)"AWS"\s*:\s*"\*"[\s\S]*?"Effect"\s*:\s*"Allow"`, block)
}
