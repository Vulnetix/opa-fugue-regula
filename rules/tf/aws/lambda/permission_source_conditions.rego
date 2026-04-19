# Adapted from https://github.com/fugue/regula (FG_R00499).
# Ported to the Vulnetix Rego input schema (input.file_contents).
# Simplified: flags aws_lambda_permission with a *.amazonaws.com service principal and no source_arn,
# or with s3/ses principal missing source_account.

package vulnetix.rules.fugue_tf_aws_lmb_02

import rego.v1

import data.vulnetix.fugue.tf

metadata := {
	"id": "FUGUE-TF-AWS-LMB-02",
	"name": "Lambda permissions with a service principal should restrict source ARN and account",
	"description": "Lambda permissions with a service principal should contain a source ARN condition. S3 and SES also require a source_account condition because their ARNs do not contain an AWS account ID.",
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
	"tags": ["terraform", "aws", "lambda"],
}

findings contains finding if {
	some p in tf.resources("aws_lambda_permission")
	principal := tf.string_attr(p.block, "principal")
	endswith(principal, ".amazonaws.com")
	not tf.has_key(p.block, "source_arn")
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("aws_lambda_permission %q has service principal but no source_arn.", [p.name]),
		"artifact_uri": p.path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": 1,
		"snippet": sprintf("%s.%s", [p.type, p.name]),
	}
}

findings contains finding if {
	some p in tf.resources("aws_lambda_permission")
	principal := tf.string_attr(p.block, "principal")
	_requires_source_account(principal)
	not tf.has_key(p.block, "source_account")
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("aws_lambda_permission %q has principal %q but no source_account.", [p.name, principal]),
		"artifact_uri": p.path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": 1,
		"snippet": sprintf("%s.%s", [p.type, p.name]),
	}
}

_requires_source_account(p) if p == "s3.amazonaws.com"

_requires_source_account(p) if p == "ses.amazonaws.com"
