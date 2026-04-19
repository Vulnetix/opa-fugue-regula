# Adapted from https://github.com/fugue/regula (FG_R00251).
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.fugue_tf_aws_rds_06

import rego.v1

import data.vulnetix.fugue.tf

metadata := {
	"id": "FUGUE-TF-AWS-RDS-06",
	"name": "RDS instances should be deployed multi-AZ",
	"description": "Provisioning multi-AZ RDS instances provides enhanced availability and durability in case of AZ failure.",
	"help_uri": "https://github.com/fugue/regula",
	"languages": ["terraform", "hcl"],
	"severity": "medium",
	"level": "warning",
	"kind": "iac",
	"cwe": ["CWE-693"],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["terraform", "aws", "rds", "availability"],
}

multi_az_supported_engines := {
	"mariadb",
	"mysql",
	"oracle-ee",
	"oracle-se1",
	"oracle-se2",
	"oracle-se",
	"postgres",
}

findings contains finding if {
	some r in tf.resources("aws_db_instance")
	engine := tf.string_attr(r.block, "engine")
	not multi_az_supported_engines[engine]
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("aws_db_instance %q uses engine %q which does not support multi-AZ.", [r.name, engine]),
		"artifact_uri": r.path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": 1,
		"snippet": sprintf("%s.%s", [r.type, r.name]),
	}
}

findings contains finding if {
	some r in tf.resources("aws_db_instance")
	engine := tf.string_attr(r.block, "engine")
	multi_az_supported_engines[engine]
	tf.is_not_true(r.block, "multi_az")
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("aws_db_instance %q does not have multi_az = true.", [r.name]),
		"artifact_uri": r.path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": 1,
		"snippet": sprintf("%s.%s", [r.type, r.name]),
	}
}
