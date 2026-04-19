# Adapted from https://github.com/fugue/regula (FG_R00222).
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.fugue_arm_mysql_no_inbound_all

import rego.v1

import data.vulnetix.fugue.arm

metadata := {
	"id": "FUGUE-ARM-MYSQL-02",
	"name": "MySQL Database server firewall rules should not permit start and end IP addresses to be 0.0.0.0",
	"description": "Adding a rule with range 0.0.0.0 to 0.0.0.0 is the same as enabling the \"Allow access to Azure services\" setting, which allows all connections from Azure, including from other subscriptions. Disabling this setting helps prevent malicious Azure users from connecting to your database and accessing sensitive data.",
	"help_uri": "https://github.com/fugue/regula",
	"languages": ["json"],
	"severity": "high",
	"level": "error",
	"kind": "iac",
	"cwe": ["CWE-284"],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["arm", "azure", "mysql", "firewall"],
}

findings contains finding if {
	some r in arm.resources("Microsoft.DBforMySQL/servers/firewallRules")
	r.resource.properties.startIpAddress == "0.0.0.0"
	r.resource.properties.endIpAddress == "0.0.0.0"
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("MySQL firewall rule %q allows all Azure services (0.0.0.0-0.0.0.0).", [r.resource.name]),
		"artifact_uri": r.path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": 1,
		"snippet": sprintf("%s/%s", [r.resource.type, r.resource.name]),
	}
}
