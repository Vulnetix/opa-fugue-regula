# Adapted from https://github.com/fugue/regula (FG_R00031).
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.fugue_cfn_cloudtrail_s3_access_logging

import rego.v1

import data.vulnetix.fugue.cfn

metadata := {
	"id": "FUGUE-CFN-CT-04",
	"name": "S3 buckets storing CloudTrail logs should have access logging enabled",
	"description": "S3 bucket access logging should be enabled on S3 buckets that store CloudTrail log files. Bucket access logging tracks access requests and can be useful in security and incident response workflows.",
	"help_uri": "https://github.com/fugue/regula",
	"languages": ["yaml", "json"],
	"severity": "medium",
	"level": "warning",
	"kind": "iac",
	"cwe": ["CWE-778"],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["cloudformation", "aws", "cloudtrail", "s3", "logging"],
}

# Best-effort bucket match: name-equal or CFN Ref to logical id.
_matches_bucket(bucket_entry, s3_bucket_name) if {
	props := cfn.properties(bucket_entry)
	props.BucketName == s3_bucket_name
}

_matches_bucket(bucket_entry, s3_bucket_name) if {
	is_object(s3_bucket_name)
	s3_bucket_name.Ref == bucket_entry.logical_id
}

_has_logging(bucket_entry) if {
	props := cfn.properties(bucket_entry)
	lc := props.LoggingConfiguration
	count(lc) > 0
}

_ct_has_logged_target_bucket(ct_entry) if {
	ct_props := cfn.properties(ct_entry)
	ct_bucket := ct_props.S3BucketName
	some b in cfn.resources("AWS::S3::Bucket")
	_matches_bucket(b, ct_bucket)
	_has_logging(b)
}

findings contains finding if {
	some r in cfn.resources("AWS::CloudTrail::Trail")
	not _ct_has_logged_target_bucket(r)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("CloudTrail Trail %q stores logs in an S3 bucket without access logging enabled.", [r.logical_id]),
		"artifact_uri": r.path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": 1,
		"snippet": sprintf("AWS::CloudTrail::Trail/%s", [r.logical_id]),
	}
}
