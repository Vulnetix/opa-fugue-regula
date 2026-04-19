# Adapted from https://github.com/fugue/regula (FG_R00018).
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.fugue_tf_aws_cf_01

import rego.v1

import data.vulnetix.fugue.tf

metadata := {
	"id": "FUGUE-TF-AWS-CF-01",
	"name": "CloudFront distributions should have geo-restrictions specified",
	"description": "CloudFront distributions should have geo-restrictions specified (whitelist or blacklist) when an organization needs to prevent users in specific geographic locations from accessing content.",
	"help_uri": "https://github.com/fugue/regula",
	"languages": ["terraform", "hcl"],
	"severity": "medium",
	"level": "warning",
	"kind": "iac",
	"cwe": ["CWE-284"],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["terraform", "aws", "cloudfront", "geo"],
}

findings contains finding if {
	some r in tf.resources("aws_cloudfront_distribution")
	not _has_geo_restriction(r.block)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("CloudFront distribution %q lacks geo_restriction with a whitelist or blacklist.", [r.name]),
		"artifact_uri": r.path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": 1,
		"snippet": sprintf("%s.%s", [r.type, r.name]),
	}
}

_has_geo_restriction(block) if {
	some restriction in tf.sub_blocks(block, "restrictions")
	some geo in tf.sub_blocks(restriction, "geo_restriction")
	rt := tf.string_attr(geo, "restriction_type")
	rt in {"whitelist", "blacklist"}
}
