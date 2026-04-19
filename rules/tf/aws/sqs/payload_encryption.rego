# Adapted from https://github.com/fugue/regula (FG_R00070).
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.fugue_tf_aws_sqs_02

import rego.v1

import data.vulnetix.fugue.tf

metadata := {
	"id": "FUGUE-TF-AWS-SQS-02",
	"name": "SQS queue server-side encryption should be enabled with KMS keys",
	"description": "SQS queues carrying sensitive data should use SSE-KMS for server-side encryption so keys and usage can be audited.",
	"help_uri": "https://github.com/fugue/regula",
	"languages": ["terraform", "hcl"],
	"severity": "high",
	"level": "error",
	"kind": "iac",
	"cwe": ["CWE-311"],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["terraform", "aws", "sqs", "encryption"],
}

findings contains finding if {
	some q in tf.resources("aws_sqs_queue")
	not tf.has_key(q.block, "kms_master_key_id")
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("aws_sqs_queue %q has no kms_master_key_id configured.", [q.name]),
		"artifact_uri": q.path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": 1,
		"snippet": sprintf("%s.%s", [q.type, q.name]),
	}
}
