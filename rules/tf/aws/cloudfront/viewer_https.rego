# Adapted from https://github.com/fugue/regula (FG_R00011).
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.fugue_tf_aws_cf_05

import rego.v1

import data.vulnetix.fugue.tf

metadata := {
	"id": "FUGUE-TF-AWS-CF-05",
	"name": "CloudFront viewer protocol policy should be https-only or redirect-to-https",
	"description": "A CloudFront distribution should only use HTTPS or redirect HTTP to HTTPS for communication between viewers and CloudFront.",
	"help_uri": "https://github.com/fugue/regula",
	"languages": ["terraform", "hcl"],
	"severity": "medium",
	"level": "warning",
	"kind": "iac",
	"cwe": ["CWE-319"],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["terraform", "aws", "cloudfront", "tls"],
}

findings contains finding if {
	some r in tf.resources("aws_cloudfront_distribution")
	some bname in {"default_cache_behavior", "ordered_cache_behavior", "cache_behavior"}
	some cb in tf.sub_blocks(r.block, bname)
	proto := tf.string_attr(cb, "viewer_protocol_policy")
	not proto in {"https-only", "redirect-to-https"}
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("CloudFront distribution %q has a cache behavior that does not enforce HTTPS (viewer_protocol_policy=%q).", [r.name, proto]),
		"artifact_uri": r.path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": 1,
		"snippet": sprintf("%s.%s", [r.type, r.name]),
	}
}
