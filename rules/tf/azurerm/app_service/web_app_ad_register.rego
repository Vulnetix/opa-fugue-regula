# Adapted from https://github.com/fugue/regula (FG_R00452).
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.fugue_tf_az_as_ad_register

import rego.v1

import data.vulnetix.fugue.tf

metadata := {
	"id": "FUGUE-TF-AZ-AS-01",
	"name": "App Service web apps should use a system-assigned managed service identity",
	"description": "App Service web apps should use a system-assigned managed service identity. A system-assigned managed service entity from Azure Active Directory enables the app to connect to other Azure services securely without the need for usernames and passwords. Eliminating credentials from the app is a more secure approach.",
	"help_uri": "https://github.com/fugue/regula",
	"languages": ["terraform", "hcl"],
	"severity": "low",
	"level": "note",
	"kind": "iac",
	"cwe": ["CWE-522"],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["terraform", "azure", "app-service", "identity"],
}

findings contains finding if {
	some r in tf.resources("azurerm_app_service")
	not _has_system_assigned_identity(r.block)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("App Service %q does not use a system-assigned managed identity.", [r.name]),
		"artifact_uri": r.path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": 1,
		"snippet": sprintf("%s.%s", [r.type, r.name]),
	}
}

_has_system_assigned_identity(block) if {
	some id in tf.sub_blocks(block, "identity")
	t := tf.string_attr(id, "type")
	lower(t) == "systemassigned"
}
