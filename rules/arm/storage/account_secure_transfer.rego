# Adapted from https://github.com/fugue/regula (FG_R00152).
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.fugue_arm_storage_account_secure_transfer

import rego.v1

import data.vulnetix.fugue.arm

metadata := {
	"id": "FUGUE-ARM-SA-03",
	"name": "Storage Accounts 'Secure transfer required' should be enabled",
	"description": "The secure transfer option enhances the security of a storage account by only allowing requests to the storage account by a secure connection. This control does not apply for custom domain names since Azure storage does not support HTTPS for custom domain names.",
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
	"tags": ["arm", "azure", "storage", "tls"],
}

# supportsHttpsTrafficOnly defaults to true starting with api version 2019-04-01.
_bad(r) if {
	r.resource.apiVersion < "2019-04-01"
	not object.get(r.resource.properties, "supportsHttpsTrafficOnly", false)
}

_bad(r) if {
	object.get(r.resource.properties, "supportsHttpsTrafficOnly", true) == false
}

findings contains finding if {
	some r in arm.resources("Microsoft.Storage/storageAccounts")
	_bad(r)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Storage account %q does not require secure transfer.", [r.resource.name]),
		"artifact_uri": r.path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": 1,
		"snippet": sprintf("%s/%s", [r.resource.type, r.resource.name]),
	}
}
