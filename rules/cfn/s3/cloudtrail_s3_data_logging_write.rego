# Adapted from https://github.com/fugue/regula (FG_R00354).
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.fugue_cfn_s3_cloudtrail_s3_data_logging_write

import rego.v1

import data.vulnetix.fugue.cfn

metadata := {
	"id": "FUGUE-CFN-S3-03",
	"name": "S3 bucket object-level logging for write events should be enabled",
	"description": "S3 bucket object-level logging for write events should be enabled. Object-level S3 events (GetObject, DeleteObject, and PutObject) are not logged by default and should be enabled for buckets containing sensitive data.",
	"help_uri": "https://github.com/fugue/regula",
	"languages": ["yaml", "json"],
	"severity": "low",
	"level": "note",
	"kind": "iac",
	"cwe": ["CWE-778"],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["cloudformation", "aws", "s3", "cloudtrail", "logging"],
}

_valid_selector_types := {"All", "WriteOnly"}

_valid_event_selector(es) if {
	_valid_selector_types[es.ReadWriteType]
}

_valid_event_selector(es) if {
	not es.ReadWriteType
}

_event_selector_matches_bucket(es, bucket) if {
	some dr in es.DataResources
	dr.Type == "AWS::S3::Object"
	some v in dr.Values
	_arn_matches_bucket(v, bucket)
}

_event_selector_matches_bucket(es, _) if {
	some dr in es.DataResources
	dr.Type == "AWS::S3::Object"
	some v in dr.Values
	v == "arn:aws:s3"
}

_event_selector_matches_bucket(es, _) if {
	some dr in es.DataResources
	dr.Type == "AWS::S3::Object"
	some v in dr.Values
	v == "arn:aws:s3:::"
}

_arn_matches_bucket(arn, bucket) if {
	props := cfn.properties(bucket)
	name := props.BucketName
	is_string(name)
	contains(arn, name)
}

_has_trails if {
	count(cfn.resources("AWS::CloudTrail::Trail")) > 0
}

_bucket_logged(bucket) if {
	some trail in cfn.resources("AWS::CloudTrail::Trail")
	tp := cfn.properties(trail)
	some es in tp.EventSelectors
	_valid_event_selector(es)
	_event_selector_matches_bucket(es, bucket)
}

findings contains finding if {
	_has_trails
	some b in cfn.resources("AWS::S3::Bucket")
	not _bucket_logged(b)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("S3 Bucket %q is not covered by any CloudTrail data-event selector logging write events.", [b.logical_id]),
		"artifact_uri": b.path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": 1,
		"snippet": sprintf("AWS::S3::Bucket/%s", [b.logical_id]),
	}
}
