# Adapted from https://github.com/fugue/regula (FG_R00225).
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.fugue_tf_az_mysql_ssl

import rego.v1

import data.vulnetix.fugue.tf

metadata := {
	"id": "FUGUE-TF-AZ-MYSQL-01",
	"name": "MySQL Database server 'enforce SSL connection' should be enabled",
	"description": "MySQL Database server 'enforce SSL connection' should be enabled. Enforcing SSL connections between your database server and your client applications helps protect against 'man in the middle' attacks by encrypting the data stream between the server and your application.",
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
	"tags": ["terraform", "azure", "mysql", "ssl"],
}

findings contains finding if {
	some r in tf.resources("azurerm_mysql_server")
	not _ssl_enforced(r.block)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("MySQL server %q does not enforce SSL connections.", [r.name]),
		"artifact_uri": r.path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": 1,
		"snippet": sprintf("%s.%s", [r.type, r.name]),
	}
}

_ssl_enforced(block) if tf.string_attr(block, "ssl_enforcement") == "Enabled"

_ssl_enforced(block) if tf.bool_attr(block, "ssl_enforcement_enabled") == true
