# Adapted from https://github.com/fugue/regula (FG_R00094).
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.fugue_tf_aws_rds_04

import rego.v1

import data.vulnetix.fugue.tf

metadata := {
	"id": "FUGUE-TF-AWS-RDS-04",
	"name": "RDS instances should use FedRAMP approved database engines",
	"description": "FedRAMP-approved database engines such as MySQL and PostgreSQL satisfy strict U.S. government requirements for securing sensitive data.",
	"help_uri": "https://github.com/fugue/regula",
	"languages": ["terraform", "hcl"],
	"severity": "low",
	"level": "note",
	"kind": "iac",
	"cwe": ["CWE-1357"],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["terraform", "aws", "rds", "compliance"],
}

supported := {
	"aurora",
	"aurora-mysql",
	"aurora-postgresql",
	"mariadb",
	"mysql",
	"oracle-ee",
	"oracle-se2",
	"oracle-se1",
	"oracle-se",
	"postgres",
	"sqlserver-ee",
	"sqlserver-se",
	"sqlserver-ex",
	"sqlserver-web",
}

findings contains finding if {
	some r in tf.resources("aws_db_instance")
	engine := tf.string_attr(r.block, "engine")
	not supported[engine]
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("aws_db_instance %q uses engine %q which is not FedRAMP-approved.", [r.name, engine]),
		"artifact_uri": r.path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": 1,
		"snippet": sprintf("%s.%s", [r.type, r.name]),
	}
}
