# Adapted from https://github.com/fugue/regula (FG_R00345).
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.fugue_tf_az_as_auth

import rego.v1

import data.vulnetix.fugue.tf

metadata := {
	"id": "FUGUE-TF-AZ-AS-02",
	"name": "App Service web app authentication should be enabled",
	"description": "App Service web app authentication should be enabled. Azure App Service Authentication is a feature that can prevent anonymous HTTP requests from reaching the API app, or authenticate those that have tokens before they reach the API app. If an anonymous request is received from a browser, App Service will redirect to a logon page. To handle the logon process, a choice from a set of identity providers can be made, or a custom authentication mechanism can be implemented.",
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
	"tags": ["terraform", "azure", "app-service", "authentication"],
}

findings contains finding if {
	some r in tf.resources("azurerm_app_service")
	not _auth_enabled(r.block)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("App Service %q does not have auth_settings.enabled = true.", [r.name]),
		"artifact_uri": r.path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": 1,
		"snippet": sprintf("%s.%s", [r.type, r.name]),
	}
}

_auth_enabled(block) if {
	some a in tf.sub_blocks(block, "auth_settings")
	tf.bool_attr(a, "enabled") == true
}
