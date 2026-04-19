# Adapted from https://github.com/fugue/regula (FG_R00027).
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.fugue_tf_aws_ct_03

import rego.v1

import data.vulnetix.fugue.tf

metadata := {
	"id": "FUGUE-TF-AWS-CT-03",
	"name": "CloudTrail log file validation should be enabled",
	"description": "File validation should be enabled on all CloudTrail logs because it provides additional integrity checking of the log data.",
	"help_uri": "https://github.com/fugue/regula",
	"languages": ["terraform", "hcl"],
	"severity": "medium",
	"level": "warning",
	"kind": "iac",
	"cwe": ["CWE-354"],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["terraform", "aws", "cloudtrail", "integrity"],
}

findings contains finding if {
	some r in tf.resources("aws_cloudtrail")
	tf.is_not_true(r.block, "enable_log_file_validation")
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("CloudTrail %q does not enable enable_log_file_validation.", [r.name]),
		"artifact_uri": r.path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": 1,
		"snippet": sprintf("%s.%s", [r.type, r.name]),
	}
}
