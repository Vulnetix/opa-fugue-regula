# Adapted from https://github.com/fugue/regula (FG_R00192).
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.fugue_tf_az_sql_no_inbound_all

import rego.v1

import data.vulnetix.fugue.tf

metadata := {
	"id": "FUGUE-TF-AZ-SQL-03",
	"name": "SQL Server firewall rules should not permit ingress from 0.0.0.0/0",
	"description": "Virtual Network security groups attached to SQL Server instances should not permit ingress from 0.0.0.0/0 to all ports and protocols. To reduce the potential attack surface for a SQL server, firewall rules should be defined with more granular IP addresses.",
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
	_invalid_range(r.block)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("SQL firewall rule %q uses an overly broad IP range (0.0.0.0 or 255.255.255.255).", [r.name]),
		"artifact_uri": r.path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": 1,
		"snippet": sprintf("%s.%s", [r.type, r.name]),
	}
}

_invalid_range(block) if tf.string_attr(block, "start_ip_address") == "0.0.0.0"

_invalid_range(block) if tf.string_attr(block, "end_ip_address") == "0.0.0.0"

_invalid_range(block) if tf.string_attr(block, "end_ip_address") == "255.255.255.255"
