# Adapted from https://github.com/fugue/regula (FG_R00052).
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.fugue_tf_aws_sns_01

import rego.v1

import data.vulnetix.fugue.tf

metadata := {
	"id": "FUGUE-TF-AWS-SNS-01",
	"name": "SNS subscriptions should not use HTTP",
	"description": "SNS subscriptions should not use HTTP as the delivery protocol; use HTTPS to enforce encryption in transit.",
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
	"tags": ["terraform", "aws", "sns", "tls"],
}

findings contains finding if {
	some s in tf.resources("aws_sns_topic_subscription")
	tf.string_attr(s.block, "protocol") == "http"
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("aws_sns_topic_subscription %q uses protocol = \"http\".", [s.name]),
		"artifact_uri": s.path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": 1,
		"snippet": sprintf("%s.%s", [s.type, s.name]),
	}
}
