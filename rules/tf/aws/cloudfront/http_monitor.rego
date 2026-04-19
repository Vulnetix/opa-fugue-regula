# Adapted from https://github.com/fugue/regula (FG_R00073).
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.fugue_tf_aws_cf_02

import rego.v1

import data.vulnetix.fugue.tf

metadata := {
	"id": "FUGUE-TF-AWS-CF-02",
	"name": "CloudFront distributions should be protected by WAFs",
	"description": "WAF should be deployed on CloudFront distributions to protect web applications from common web exploits that could affect application availability, compromise security, or consume excessive resources.",
	"help_uri": "https://github.com/fugue/regula",
	"languages": ["terraform", "hcl"],
	"severity": "medium",
	"level": "warning",
	"kind": "iac",
	"cwe": ["CWE-693"],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["terraform", "aws", "cloudfront", "waf"],
}

findings contains finding if {
	some r in tf.resources("aws_cloudfront_distribution")
	not tf.has_key(r.block, "web_acl_id")
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("CloudFront distribution %q has no web_acl_id (WAF) attached.", [r.name]),
		"artifact_uri": r.path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": 1,
		"snippet": sprintf("%s.%s", [r.type, r.name]),
	}
}
