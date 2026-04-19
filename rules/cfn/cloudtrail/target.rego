# Adapted from https://github.com/fugue/regula (FG_R00028).
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.fugue_cfn_cloudtrail_target

import rego.v1

import data.vulnetix.fugue.cfn

metadata := {
	"id": "FUGUE-CFN-CT-05",
	"name": "S3 buckets storing CloudTrail logs should not be publicly readable",
	"description": "S3 bucket ACLs should not have public access on S3 buckets that store CloudTrail log files. Allowing public access to CloudTrail log data may aid an adversary in identifying weaknesses in the affected account.",
	"help_uri": "https://github.com/fugue/regula",
	"languages": ["yaml", "json"],
	"severity": "critical",
	"level": "error",
	"kind": "iac",
	"cwe": ["CWE-284"],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["cloudformation", "aws", "cloudtrail", "s3", "public-access"],
}

_matches_bucket(bucket_entry, s3_bucket_name) if {
	props := cfn.properties(bucket_entry)
	props.BucketName == s3_bucket_name
}

_matches_bucket(bucket_entry, s3_bucket_name) if {
	is_object(s3_bucket_name)
	s3_bucket_name.Ref == bucket_entry.logical_id
}

_bucket_public_acl(bucket_entry) if {
	props := cfn.properties(bucket_entry)
	props.AccessControl == "PublicRead"
}

_bucket_public_acl(bucket_entry) if {
	props := cfn.properties(bucket_entry)
	props.AccessControl == "PublicReadWrite"
}

_is_cloudtrail_bucket(bucket_entry) if {
	some ct in cfn.resources("AWS::CloudTrail::Trail")
	ct_props := cfn.properties(ct)
	_matches_bucket(bucket_entry, ct_props.S3BucketName)
}

findings contains finding if {
	some b in cfn.resources("AWS::S3::Bucket")
	_is_cloudtrail_bucket(b)
	_bucket_public_acl(b)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("S3 bucket %q stores CloudTrail logs and has a public-read ACL.", [b.logical_id]),
		"artifact_uri": b.path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": 1,
		"snippet": sprintf("AWS::S3::Bucket/%s", [b.logical_id]),
	}
}
