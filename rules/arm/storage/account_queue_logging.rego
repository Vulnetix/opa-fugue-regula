# Adapted from https://github.com/fugue/regula (FG_R00440).
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.fugue_arm_storage_account_queue_logging

import rego.v1

import data.vulnetix.fugue.arm

metadata := {
	"id": "FUGUE-ARM-SA-02",
	"name": "Storage Queue logging should be enabled for read, write, and delete requests",
	"description": "Storage account read, write, and delete logging for Storage Queues is not enabled by default. Logging should be enabled so that users can monitor queues for security and performance issues.",
	"help_uri": "https://github.com/fugue/regula",
	"languages": ["json"],
	"severity": "medium",
	"level": "warning",
	"kind": "iac",
	"cwe": ["CWE-778"],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["arm", "azure", "storage", "logging"],
}

_all_logged(r) if {
	cats := {lower(log.category) |
		some log in object.get(r.resource.properties, "logs", [])
		log.enabled == true
	}
	"storageread" in cats
	"storagewrite" in cats
	"storagedelete" in cats
}

findings contains finding if {
	some r in arm.resources("Microsoft.Storage/storageAccounts/queueServices/providers/diagnosticsettings")
	not _all_logged(r)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Storage queue diagnostic setting %q does not log all read/write/delete categories.", [r.resource.name]),
		"artifact_uri": r.path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": 1,
		"snippet": sprintf("%s/%s", [r.resource.type, r.resource.name]),
	}
}
