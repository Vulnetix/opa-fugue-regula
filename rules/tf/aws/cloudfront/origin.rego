# Adapted from https://github.com/fugue/regula (FG_R00010).
# Ported to the Vulnetix Rego input schema (input.file_contents).
# Limitation: variable/module-resolved origin domain names are not evaluated.

package vulnetix.rules.fugue_tf_aws_cf_04

import rego.v1

import data.vulnetix.fugue.tf

metadata := {
	"id": "FUGUE-TF-AWS-CF-04",
	"name": "CloudFront distribution origin should use S3 or https-only protocol",
	"description": "CloudFront distribution origin should be set to S3 or origin protocol policy should be set to https-only to encrypt traffic to custom origins.",
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
	some origin in tf.sub_blocks(r.block, "origin")
	not _valid_origin(origin)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("CloudFront distribution %q has an origin that is not S3 or https-only.", [r.name]),
		"artifact_uri": r.path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": 1,
		"snippet": sprintf("%s.%s", [r.type, r.name]),
	}
}

_valid_origin(origin) if {
	d := tf.string_attr(origin, "domain_name")
	regex.match(`s3(\.[a-z\-]+?-[0-9]+?)?\.amazonaws\.com$`, d)
}

_valid_origin(origin) if {
	some coc in tf.sub_blocks(origin, "custom_origin_config")
	tf.string_attr(coc, "origin_protocol_policy") == "https-only"
}

_valid_origin(origin) if {
	# HCL reference to aws_s3_bucket.<name>.* as domain_name
	regex.match(`domain_name\s*=\s*aws_s3_bucket\.`, origin)
}
