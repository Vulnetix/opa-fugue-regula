# Adapted from https://github.com/fugue/regula (FG_R00221).
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.fugue_tf_az_sql_no_inbound_azure

import rego.v1

import data.vulnetix.fugue.tf

metadata := {
	"id": "FUGUE-TF-AZ-SQL-04",
	"name": "SQL Server firewall rules should not permit start/end IP = 0.0.0.0",
	"description": "SQL Server firewall rules should not permit start and end IP addresses to be 0.0.0.0. Adding a rule with range 0.0.0.0 to 0.0.0.0 is the same as enabling the 'Allow access to Azure services' setting, which allows all connections from Azure.",
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
	"tags": ["terraform", "azure", "sql", "firewall"],
}

findings contains finding if {
	some r in tf.resources("azurerm_sql_firewall_rule")
	tf.string_attr(r.block, "start_ip_address") == "0.0.0.0"
	tf.string_attr(r.block, "end_ip_address") == "0.0.0.0"
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("SQL firewall rule %q permits all Azure services (start/end IP = 0.0.0.0).", [r.name]),
		"artifact_uri": r.path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": 1,
		"snippet": sprintf("%s.%s", [r.type, r.name]),
	}
}
