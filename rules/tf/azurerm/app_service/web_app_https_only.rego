# Adapted from https://github.com/fugue/regula (FG_R00346).
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.fugue_tf_az_as_https_only

import rego.v1

import data.vulnetix.fugue.tf

metadata := {
	"id": "FUGUE-TF-AZ-AS-03",
	"name": "App Service web apps should have 'HTTPS only' enabled",
	"description": "App Service web apps should have 'HTTPS only' enabled. Azure Web Apps allows sites to run under both HTTP and HTTPS by default. Web apps can be accessed by anyone using non-secure HTTP links by default. Non-secure HTTP requests can be restricted and all HTTP requests redirected to the secure HTTPS port. It is recommended to enforce HTTPS-only traffic.",
	"help_uri": "https://github.com/fugue/regula",
	"languages": ["terraform", "hcl"],
	"severity": "high",
	"level": "error",
	"kind": "iac",
	"cwe": ["CWE-319"],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["terraform", "azure", "app-service", "https"],
}

findings contains finding if {
	some r in tf.resources("azurerm_app_service")
	not tf.bool_attr(r.block, "https_only") == true
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("App Service %q does not have https_only = true.", [r.name]),
		"artifact_uri": r.path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": 1,
		"snippet": sprintf("%s.%s", [r.type, r.name]),
	}
}
