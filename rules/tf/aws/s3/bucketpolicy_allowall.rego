# Adapted from https://github.com/fugue/regula (FG_R00210).
# Ported to the Vulnetix Rego input schema (input.file_contents).
# Simplified: flags aws_s3_bucket_policy bodies with Allow/*/* wildcard statements.

package vulnetix.rules.fugue_tf_aws_s3_05

import rego.v1

import data.vulnetix.fugue.tf

metadata := {
	"id": "FUGUE-TF-AWS-S3-05",
	"name": "S3 bucket policies should not allow all actions for all principals",
	"description": "S3 bucket policies should not use wildcard actions and principals except in very specific administrative situations.",
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
	tf.has_wildcard_allow_star(p.block)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("aws_s3_bucket_policy %q allows Action:* on Resource:* (wildcard).", [p.name]),
		"artifact_uri": p.path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": 1,
		"snippet": sprintf("%s.%s", [p.type, p.name]),
	}
}
