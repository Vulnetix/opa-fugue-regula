# Adapted from https://github.com/fugue/regula (FG_R00229).
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.fugue_cfn_s3_block_public_access

import rego.v1

import data.vulnetix.fugue.cfn

metadata := {
	"id": "FUGUE-CFN-S3-01",
	"name": "S3 buckets should have all block public access options enabled",
	"description": "S3 buckets should have all `block public access` options enabled (BlockPublicAcls, IgnorePublicAcls, BlockPublicPolicy, RestrictPublicBuckets) to help prevent the risk of a data breach.",
	"help_uri": "https://github.com/fugue/regula",
	"languages": ["yaml", "json"],
	"severity": "high",
	"level": "error",
	"kind": "iac",
	"cwe": ["CWE-284"],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["cloudformation", "aws", "s3", "public-access"],
}

_all_blocks_enabled(props) if {
	block := props.PublicAccessBlockConfiguration
	block.BlockPublicAcls == true
	block.BlockPublicPolicy == true
	block.IgnorePublicAcls == true
	block.RestrictPublicBuckets == true
}

findings contains finding if {
	some r in cfn.resources("AWS::S3::Bucket")
	props := cfn.properties(r)
	not _all_blocks_enabled(props)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("S3 Bucket %q does not have all four PublicAccessBlockConfiguration settings enabled.", [r.logical_id]),
		"artifact_uri": r.path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": 1,
		"snippet": sprintf("AWS::S3::Bucket/%s", [r.logical_id]),
	}
}
