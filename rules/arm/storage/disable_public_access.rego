# Adapted from https://github.com/fugue/regula (FG_R00207).
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.fugue_arm_storage_disable_public_access

import rego.v1

import data.vulnetix.fugue.arm

metadata := {
	"id": "FUGUE-ARM-SA-05",
	"name": "Blob Storage containers should have public access disabled",
	"description": "Anonymous, public read access to a container and its blobs can be enabled in Azure Blob storage. It grants read-only access to these resources without sharing the account key, and without requiring a shared access signature. It is recommended not to provide anonymous access to blob containers until, and unless, it is strongly desired. A shared access signature token should be used for providing controlled and timed access to blob containers.",
	"help_uri": "https://github.com/fugue/regula",
	"languages": ["json"],
	"severity": "critical",
	"level": "error",
	"kind": "iac",
	"cwe": ["CWE-284"],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["arm", "azure", "storage", "public-access"],
}

_public_options := {"blob", "container"}

_bad(r) if {
	lower(object.get(r.resource.properties, "publicAccess", "")) in _public_options
}

findings contains finding if {
	some r in arm.resources("Microsoft.Storage/storageAccounts/blobServices/containers")
	_bad(r)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Blob container %q allows public access.", [r.resource.name]),
		"artifact_uri": r.path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": 1,
		"snippet": sprintf("%s/%s", [r.resource.type, r.resource.name]),
	}
}
