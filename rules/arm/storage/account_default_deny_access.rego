# Adapted from https://github.com/fugue/regula (FG_R00154).
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.fugue_arm_storage_account_default_deny_access

import rego.v1

import data.vulnetix.fugue.arm

metadata := {
	"id": "FUGUE-ARM-SA-01",
	"name": "Storage Account default network access rules should deny all traffic",
	"description": "Storage accounts should be configured to deny access to traffic from all networks. Access can be granted to traffic from specific Azure Virtual networks, allowing a secure network boundary for specific applications to be built. Access can also be granted to public internet IP address ranges, to enable connections from specific internet or on-premises clients. When network rules are configured, only applications from allowed networks can access a storage account. When calling from an allowed network, applications continue to require proper authorization (a valid access key or SAS token) to access the storage account.",
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
	"tags": ["arm", "azure", "storage", "network-access"],
}

_ok(r) if {
	acls := object.get(r.resource.properties, "networkAcls", {})
	lower(object.get(acls, "defaultAction", "")) == "deny"
}

findings contains finding if {
	some r in arm.resources("Microsoft.Storage/storageAccounts")
	not _ok(r)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Storage account %q default network action is not 'deny'.", [r.resource.name]),
		"artifact_uri": r.path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": 1,
		"snippet": sprintf("%s/%s", [r.resource.type, r.resource.name]),
	}
}
