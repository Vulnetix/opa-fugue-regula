# Adapted from https://github.com/fugue/regula (FG_R00208).
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.fugue_tf_az_sa_network_trust_microsoft

import rego.v1

import data.vulnetix.fugue.tf

metadata := {
	"id": "FUGUE-TF-AZ-SA-03",
	"name": "Storage Accounts should have 'Trusted Microsoft Services' enabled",
	"description": "Storage Accounts should have 'Trusted Microsoft Services' enabled. Enabling 'Trusted Microsoft Services' allows Azure Backup, Azure Site Recovery, Azure Networking, Azure Monitor, and other Azure services to access your storage account and bypass any firewall rules.",
	"help_uri": "https://github.com/fugue/regula",
	"languages": ["terraform", "hcl"],
	"severity": "medium",
	"level": "warning",
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
	not _bypasses_azure_services(nr.block)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Storage account network rules %q do not include 'AzureServices' in bypass.", [nr.name]),
		"artifact_uri": nr.path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": 1,
		"snippet": sprintf("%s.%s", [nr.type, nr.name]),
	}
}

findings contains finding if {
	some sa in tf.resources("azurerm_storage_account")
	not _sa_trusts_microsoft(sa)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Storage account %q does not have 'AzureServices' in network_rules.bypass (inline or external).", [sa.name]),
		"artifact_uri": sa.path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": 1,
		"snippet": sprintf("%s.%s", [sa.type, sa.name]),
	}
}

_bypasses_azure_services(block) if {
	bypass := tf.string_list_attr(block, "bypass")
	some b in bypass
	lower(b) == "azureservices"
}

_sa_trusts_microsoft(sa) if {
	some nr in tf.sub_blocks(sa.block, "network_rules")
	_bypasses_azure_services(nr)
}

_sa_trusts_microsoft(sa) if {
	some nr in tf.resources("azurerm_storage_account_network_rules")
	tf.references(nr.block, "azurerm_storage_account", sa.name)
	_bypasses_azure_services(nr.block)
}
