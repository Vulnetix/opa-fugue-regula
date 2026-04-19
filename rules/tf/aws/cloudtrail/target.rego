# Adapted from https://github.com/fugue/regula (FG_R00028).
# Ported to the Vulnetix Rego input schema (input.file_contents).
# Simplified: flags CloudTrail target buckets with a literal public-read/public-read-write acl.

package vulnetix.rules.fugue_tf_aws_ct_06

import rego.v1

import data.vulnetix.fugue.tf

metadata := {
	"id": "FUGUE-TF-AWS-CT-06",
	"name": "CloudTrail S3 target bucket ACLs should not be public",
	"description": "S3 bucket ACLs should not allow public access on buckets that store CloudTrail log files. Public access may aid adversaries in identifying weaknesses.",
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
	"tags": ["terraform", "aws", "cloudtrail", "s3", "public"],
}

public_acls := {"public-read", "public-read-write"}

findings contains finding if {
	some r in tf.resources("aws_cloudtrail")
	matches := regex.find_all_string_submatch_n(`s3_bucket_name\s*=\s*aws_s3_bucket\.([A-Za-z_][A-Za-z0-9_]*)\b`, r.block, -1)
	some m in matches
	bucket_name := m[1]
	_bucket_public(bucket_name)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("CloudTrail %q target bucket %q has a public ACL.", [r.name, bucket_name]),
		"artifact_uri": r.path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": 1,
		"snippet": sprintf("%s.%s", [r.type, r.name]),
	}
}

_bucket_public(bucket_name) if {
	some b in tf.resources("aws_s3_bucket")
	b.name == bucket_name
	acl := tf.string_attr(b.block, "acl")
	acl in public_acls
}

_bucket_public(bucket_name) if {
	some a in tf.resources("aws_s3_bucket_acl")
	regex.match(sprintf(`bucket\s*=\s*aws_s3_bucket\.%s\b`, [bucket_name]), a.block)
	acl := tf.string_attr(a.block, "acl")
	acl in public_acls
}
