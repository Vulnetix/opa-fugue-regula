# Adapted from https://github.com/fugue/regula (FG_R00208).
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.fugue_arm_storage_account_trusted_ms_services

import rego.v1

import data.vulnetix.fugue.arm

metadata := {
	"id": "FUGUE-ARM-SA-04",
	"name": "Storage Accounts should have 'Trusted Microsoft Services' enabled",
	"description": "Some Microsoft services that interact with storage accounts operate from networks that can't be granted access through network rules. Enabling \"Trusted Microsoft Services\" allows Azure Backup, Azure Site Recovery, Azure Networking, Azure Monitor, and other Azure services to access your storage account and bypass any firewall rules.",
	"help_uri": "https://github.com/fugue/regula",
	"languages": ["json"],
	"severity": "medium",
	"level": "warning",
	"kind": "iac",
	"cwe": ["CWE-284"],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["arm", "azure", "storage", "network-access"],
}

_ok(r) if {
	acls := object.get(r.resource.properties, "networkAcls", {})
	bypass := object.get(acls, "bypass", "")
	contains(bypass, "AzureServices")
}

findings contains finding if {
	some r in arm.resources("Microsoft.Storage/storageAccounts")
	not _ok(r)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Storage account %q does not include 'AzureServices' in networkAcls.bypass.", [r.resource.name]),
		"artifact_uri": r.path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": 1,
		"snippet": sprintf("%s/%s", [r.resource.type, r.resource.name]),
	}
}
