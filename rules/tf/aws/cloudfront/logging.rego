# Adapted from https://github.com/fugue/regula (FG_R00067).
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.fugue_tf_aws_cf_03

import rego.v1

import data.vulnetix.fugue.tf

metadata := {
	"id": "FUGUE-TF-AWS-CF-03",
	"name": "CloudFront access logging should be enabled",
	"description": "CloudFront distribution access logging should be enabled in order to track viewer requests for content, analyze statistics, and perform security audits.",
	"help_uri": "https://github.com/fugue/regula",
	"languages": ["terraform", "hcl"],
	"severity": "medium",
	"level": "warning",
	"kind": "iac",
	"cwe": ["CWE-778"],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["terraform", "aws", "cloudfront", "logging"],
}

findings contains finding if {
	some r in tf.resources("aws_cloudfront_distribution")
	not _has_logging(r.block)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("CloudFront distribution %q has no logging_config.", [r.name]),
		"artifact_uri": r.path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": 1,
		"snippet": sprintf("%s.%s", [r.type, r.name]),
	}
}

_has_logging(block) if {
	some lc in tf.sub_blocks(block, "logging_config")
	tf.has_key(lc, "bucket")
}
