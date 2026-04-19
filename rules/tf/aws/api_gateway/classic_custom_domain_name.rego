# Adapted from https://github.com/fugue/regula (FG_R00375).
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.fugue_tf_aws_apigw_01

import rego.v1

import data.vulnetix.fugue.tf

metadata := {
	"id": "FUGUE-TF-AWS-APIGW-01",
	"name": "API Gateway classic custom domains should use secure TLS protocol versions (1.2 and above)",
	"description": "API Gateway classic custom domains should use secure TLS protocol versions (1.2 and above). Versions prior to TLS 1.2 are deprecated and usage may pose security risks.",
	"help_uri": "https://github.com/fugue/regula",
	"languages": ["terraform", "hcl"],
	"severity": "medium",
	"level": "warning",
	"kind": "iac",
	"cwe": ["CWE-327"],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["terraform", "aws", "api_gateway", "tls"],
}

findings contains finding if {
	some r in tf.resources("aws_api_gateway_domain_name")
	tf.string_attr(r.block, "security_policy") == "TLS_1_0"
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("API Gateway domain %q uses deprecated TLS_1_0 security_policy.", [r.name]),
		"artifact_uri": r.path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": 1,
		"snippet": sprintf("%s.%s", [r.type, r.name]),
	}
}
