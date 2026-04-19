# Adapted from https://github.com/fugue/regula (FG_R00100).
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.fugue_cfn_s3_https_access

import rego.v1

import data.vulnetix.fugue.cfn

metadata := {
	"id": "FUGUE-CFN-S3-05",
	"name": "S3 bucket policies should only allow requests that use HTTPS",
	"description": "S3 bucket policies should deny all HTTP requests and allow only HTTPS requests. HTTPS uses TLS to encrypt data, preserving integrity and preventing tampering.",
	"help_uri": "https://github.com/fugue/regula",
	"languages": ["yaml", "json"],
	"severity": "medium",
	"level": "warning",
	"kind": "iac",
	"cwe": ["CWE-311"],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["cloudformation", "aws", "s3", "tls"],
}

_as_array(x) := [x] if not is_array(x)
_as_array(x) := x if is_array(x)

_matches_bucket(bucket_entry, bucket_ref) if {
	props := cfn.properties(bucket_entry)
	props.BucketName == bucket_ref
}

_matches_bucket(bucket_entry, bucket_ref) if {
	is_object(bucket_ref)
	bucket_ref.Ref == bucket_entry.logical_id
}

_related_actions := {"s3:GetObject", "s3:*", "*"}

_specifies_secure_transport(statement) if {
	vals := _as_array(statement.Condition.Bool["aws:SecureTransport"])
	some v in vals
	v == false
	statement.Effect == "Deny"
	actions := _as_array(statement.Action)
	some a in actions
	_related_actions[a]
}

_policies_for_bucket(bucket) := [p |
	some p in cfn.resources("AWS::S3::BucketPolicy")
	pp := cfn.properties(p)
	_matches_bucket(bucket, pp.Bucket)
]

_bucket_enforces_https(bucket) if {
	some p in _policies_for_bucket(bucket)
	pp := cfn.properties(p)
	some s in _as_array(pp.PolicyDocument.Statement)
	_specifies_secure_transport(s)
}

findings contains finding if {
	some b in cfn.resources("AWS::S3::Bucket")
	not _bucket_enforces_https(b)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("S3 Bucket %q has no attached BucketPolicy statement denying non-HTTPS requests.", [b.logical_id]),
		"artifact_uri": b.path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": 1,
		"snippet": sprintf("AWS::S3::Bucket/%s", [b.logical_id]),
	}
}
