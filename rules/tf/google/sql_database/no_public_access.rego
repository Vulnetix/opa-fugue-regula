# Adapted from https://github.com/fugue/regula (FG_R00434).
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.fugue_tf_gcp_sql_no_public_access

import rego.v1

import data.vulnetix.fugue.tf

metadata := {
	"id": "FUGUE-TF-GCP-SQL-03",
	"name": "SQL database instances should not permit access from 0.0.0.0/0",
	"description": "SQL database instances should not permit access from 0.0.0.0/0. SQL database instances permitting access from 0.0.0.0/0 are allowing access from anywhere in the world. To minimize its attack surface, a database server should only permit connections from trusted IP addresses.",
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
	"tags": ["terraform", "gcp", "sql", "public-access"],
}

findings contains finding if {
	some r in tf.resources("google_sql_database_instance")
	_has_public_authorized_network(r.block)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("google_sql_database_instance %q has an authorized_network with value 0.0.0.0/0.", [r.name]),
		"artifact_uri": r.path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": 1,
		"snippet": sprintf("%s.%s", [r.type, r.name]),
	}
}

_has_public_authorized_network(block) if {
	some settings in tf.sub_blocks(block, "settings")
	some ip in tf.sub_blocks(settings, "ip_configuration")
	some an in tf.sub_blocks(ip, "authorized_networks")
	tf.string_attr(an, "value") == "0.0.0.0/0"
}
