# Adapted from https://github.com/fugue/regula (FG_R00278).
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.fugue_tf_aws_rds_07

import rego.v1

import data.vulnetix.fugue.tf

metadata := {
	"id": "FUGUE-TF-AWS-RDS-07",
	"name": "RDS instances should not be publicly accessible",
	"description": "Publicly accessible RDS instances allow any AWS user or anonymous user access to the data in the database.",
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
	"tags": ["terraform", "aws", "rds", "public"],
}

findings contains finding if {
	some r in tf.resources("aws_db_instance")
	tf.bool_attr(r.block, "publicly_accessible") == true
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("aws_db_instance %q has publicly_accessible = true.", [r.name]),
		"artifact_uri": r.path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": 1,
		"snippet": sprintf("%s.%s", [r.type, r.name]),
	}
}
