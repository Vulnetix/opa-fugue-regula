# Adapted from https://github.com/fugue/regula (FG_R00049).
# Ported to the Vulnetix Rego input schema (input.file_contents).
# Simplified: flags aws_sqs_queue whose policy text contains an Allow+Principal:* statement with no Condition.

package vulnetix.rules.fugue_tf_aws_sqs_01

import rego.v1

import data.vulnetix.fugue.tf

metadata := {
	"id": "FUGUE-TF-AWS-SQS-01",
	"name": "SQS access policies should not allow wildcard access",
	"description": "SQS policies should not permit all principals to access SQS queues; follow the principle of least privilege.",
	"help_uri": "https://github.com/fugue/regula",
	"languages": ["terraform", "hcl"],
	"severity": "critical",
	"level": "error",
	"kind": "iac",
	"cwe": ["CWE-284"],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["terraform", "aws", "sqs", "policy"],
}

findings contains finding if {
	some q in tf.resources("aws_sqs_queue")
	_has_wildcard_principal(q.block)
	not _has_condition(q.block)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("aws_sqs_queue %q has a policy allowing all principals without conditions.", [q.name]),
		"artifact_uri": q.path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": 1,
		"snippet": sprintf("%s.%s", [q.type, q.name]),
	}
}

_has_wildcard_principal(block) if {
	regex.match(`(?s)"Effect"\s*:\s*"Allow"[\s\S]*?"Principal"\s*:\s*"\*"`, block)
}

_has_wildcard_principal(block) if {
	regex.match(`(?s)"Principal"\s*:\s*"\*"[\s\S]*?"Effect"\s*:\s*"Allow"`, block)
}

_has_condition(block) if regex.match(`"Condition"\s*:`, block)
