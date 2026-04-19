# Adapted from https://github.com/fugue/regula (FG_R00433).
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.fugue_tf_gcp_sql_require_ssl

import rego.v1

import data.vulnetix.fugue.tf

metadata := {
	"id": "FUGUE-TF-GCP-SQL-12",
	"name": "SQL database instances should require incoming connections to use SSL",
	"description": "SQL database instances should require incoming connections to use SSL. SQL database instances supporting plaintext connections are susceptible to man-in-the-middle attacks that can reveal sensitive data like credentials, queries, and datasets. It is therefore recommended to always use SSL encryption for database connections.",
	"help_uri": "https://github.com/fugue/regula",
	"languages": ["terraform", "hcl"],
	"severity": "medium",
	"level": "warning",
	"kind": "iac",
	"cwe": ["CWE-319"],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["terraform", "gcp", "sql", "tls"],
}

findings contains finding if {
	some r in tf.resources("google_sql_database_instance")
	not _requires_ssl(r.block)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("google_sql_database_instance %q does not set ip_configuration.require_ssl = true.", [r.name]),
		"artifact_uri": r.path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": 1,
		"snippet": sprintf("%s.%s", [r.type, r.name]),
	}
}

_requires_ssl(block) if {
	some settings in tf.sub_blocks(block, "settings")
	some ip in tf.sub_blocks(settings, "ip_configuration")
	tf.bool_attr(ip, "require_ssl") == true
}
