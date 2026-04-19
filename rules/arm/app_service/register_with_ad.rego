# Adapted from https://github.com/fugue/regula (FG_R00452).
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.fugue_arm_app_service_register_with_ad

import rego.v1

import data.vulnetix.fugue.arm

metadata := {
	"id": "FUGUE-ARM-AS-05",
	"name": "App Service web apps should use a system-assigned managed service identity",
	"description": "A system-assigned managed service entity from Azure Active Directory enables the app to connect to other Azure services securely without the need for usernames and passwords. Eliminating credentials from the app is a more secure approach.",
	"help_uri": "https://github.com/fugue/regula",
	"languages": ["json"],
	"severity": "low",
	"level": "note",
	"kind": "iac",
	"cwe": ["CWE-522"],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["arm", "azure", "app-service", "managed-identity"],
}

_is_system_assigned(s) if {
	t := object.get(s.resource, "identity", {})
	lower(object.get(t, "type", "")) == "systemassigned"
}

findings contains finding if {
	some s in arm.resources("Microsoft.Web/sites")
	not _is_system_assigned(s)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("App Service site %q does not use a system-assigned managed identity.", [s.resource.name]),
		"artifact_uri": s.path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": 1,
		"snippet": sprintf("%s/%s", [s.resource.type, s.resource.name]),
	}
}
