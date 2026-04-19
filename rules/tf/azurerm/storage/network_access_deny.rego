# Adapted from https://github.com/fugue/regula (FG_R00154).
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.fugue_tf_az_sa_network_access_deny

import rego.v1

import data.vulnetix.fugue.tf

metadata := {
	"id": "FUGUE-TF-AZ-SA-02",
	"name": "Storage Account default network access rules should deny all traffic",
	"description": "Storage Account default network access rules should deny all traffic. Storage accounts should be configured to deny access to traffic from all networks, granting access only to specific Azure Virtual networks or public IP ranges.",
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
	"tags": ["terraform", "azure", "storage", "network"],
}

findings contains finding if {
	some nr in tf.resources("azurerm_storage_account_network_rules")
	not _default_action_deny(nr.block)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Storage account network rules %q do not set default_action = \"Deny\".", [nr.name]),
		"artifact_uri": nr.path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": 1,
		"snippet": sprintf("%s.%s", [nr.type, nr.name]),
	}
}

findings contains finding if {
	some sa in tf.resources("azurerm_storage_account")
	some nr in tf.sub_blocks(sa.block, "network_rules")
	not _default_action_deny(nr)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Storage account %q has inline network_rules with default_action != \"Deny\".", [sa.name]),
		"artifact_uri": sa.path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": 1,
		"snippet": sprintf("%s.%s", [sa.type, sa.name]),
	}
}

_default_action_deny(block) if lower(tf.string_attr(block, "default_action")) == "deny"
