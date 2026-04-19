# Adapted from https://github.com/fugue/regula (FG_R00069).
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.fugue_tf_aws_ddb_01

import rego.v1

import data.vulnetix.fugue.tf

metadata := {
	"id": "FUGUE-TF-AWS-DDB-01",
	"name": "DynamoDB tables should be encrypted with AWS or customer managed KMS keys",
	"description": "DynamoDB tables should have server_side_encryption enabled with AWS managed or customer managed KMS keys.",
	"help_uri": "https://github.com/fugue/regula",
	"languages": ["terraform", "hcl"],
	"severity": "medium",
	"level": "warning",
	"kind": "iac",
	"cwe": ["CWE-311"],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["terraform", "aws", "dynamodb", "encryption"],
}

findings contains finding if {
	some r in tf.resources("aws_dynamodb_table")
	not _sse_enabled(r.block)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("DynamoDB table %q does not enable server_side_encryption.", [r.name]),
		"artifact_uri": r.path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": 1,
		"snippet": sprintf("%s.%s", [r.type, r.name]),
	}
}

_sse_enabled(block) if {
	some sse in tf.sub_blocks(block, "server_side_encryption")
	tf.bool_attr(sse, "enabled") == true
}
