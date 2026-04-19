# Adapted from https://github.com/fugue/regula (FG_R00276).
# Ported to the Vulnetix Rego input schema (input.file_contents).
# Simplified: flags aws_lambda_permission with principal = "*".

package vulnetix.rules.fugue_tf_aws_lmb_01

import rego.v1

import data.vulnetix.fugue.tf

metadata := {
	"id": "FUGUE-TF-AWS-LMB-01",
	"name": "Lambda function policies should not allow global access",
	"description": "Publicly accessible Lambda functions may be runnable by anyone and could drive up costs, disrupt services, or leak data.",
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
	"tags": ["terraform", "aws", "lambda"],
}

findings contains finding if {
	some p in tf.resources("aws_lambda_permission")
	tf.string_attr(p.block, "principal") == "*"
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("aws_lambda_permission %q grants principal = \"*\".", [p.name]),
		"artifact_uri": p.path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": 1,
		"snippet": sprintf("%s.%s", [p.type, p.name]),
	}
}
