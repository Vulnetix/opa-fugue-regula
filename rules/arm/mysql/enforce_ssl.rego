# Adapted from https://github.com/fugue/regula (FG_R00225).
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.fugue_arm_mysql_enforce_ssl

import rego.v1

import data.vulnetix.fugue.arm

metadata := {
	"id": "FUGUE-ARM-MYSQL-01",
	"name": "MySQL Database server 'enforce SSL connection' should be enabled",
	"description": "Enforcing SSL connections between your database server and your client applications helps protect against \"man in the middle\" attacks by encrypting the data stream between the server and your application.",
	"help_uri": "https://github.com/fugue/regula",
	"languages": ["json"],
	"severity": "medium",
	"level": "warning",
	"kind": "iac",
	"cwe": ["CWE-319"],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["arm", "azure", "mysql", "tls"],
}

_ok(r) if {
	lower(object.get(r.resource.properties, "sslEnforcement", "")) == "enabled"
}

findings contains finding if {
	some r in arm.resources("Microsoft.DBforMySQL/servers")
	not _ok(r)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("MySQL server %q does not enforce SSL connections.", [r.resource.name]),
		"artifact_uri": r.path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": 1,
		"snippet": sprintf("%s/%s", [r.resource.type, r.resource.name]),
	}
}
