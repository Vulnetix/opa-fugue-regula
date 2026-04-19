# Adapted from https://github.com/fugue/regula (FG_R00211).
# Ported to the Vulnetix Rego input schema (input.file_contents).
# Simplified: text-scans aws_s3_bucket_policy body for Allow/s3:List*/Principal "*" statements.

package vulnetix.rules.fugue_tf_aws_s3_06

import rego.v1

import data.vulnetix.fugue.tf

metadata := {
	"id": "FUGUE-TF-AWS-S3-06",
	"name": "S3 bucket policies should not allow list actions for all principals",
	"description": "S3 bucket list actions enable adversaries to enumerate buckets and objects; scope these actions to specific users and roles.",
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
	"tags": ["terraform", "aws", "s3", "policy"],
}

findings contains finding if {
	some p in tf.resources("aws_s3_bucket_policy")
	_has_public_list(p.block)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("aws_s3_bucket_policy %q grants s3:List* to Principal \"*\".", [p.name]),
		"artifact_uri": p.path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": 1,
		"snippet": sprintf("%s.%s", [p.type, p.name]),
	}
}

_has_public_list(block) if {
	regex.match(`(?s)"Effect"\s*:\s*"Allow"[\s\S]*?"Action"\s*:\s*"s3:List[^"]*"[\s\S]*?"Principal"\s*:\s*"\*"`, block)
}

_has_public_list(block) if {
	regex.match(`(?s)"Effect"\s*:\s*"Allow"[\s\S]*?"Principal"\s*:\s*"\*"[\s\S]*?"Action"\s*:\s*"s3:List[^"]*"`, block)
}

_has_public_list(block) if {
	regex.match(`(?s)"Action"\s*:\s*\[[^\]]*"s3:List[^"]*"[^\]]*\][\s\S]*?"Principal"\s*:\s*"\*"`, block)
}
