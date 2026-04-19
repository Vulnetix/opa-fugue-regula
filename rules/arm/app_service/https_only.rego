# Adapted from https://github.com/fugue/regula (FG_R00346).
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.fugue_arm_app_service_https_only

import rego.v1

import data.vulnetix.fugue.arm

metadata := {
	"id": "FUGUE-ARM-AS-03",
	"name": "App Service web apps should have 'HTTPS only' enabled",
	"description": "Azure Web Apps allows sites to run under both HTTP and HTTPS by default. Web apps can be accessed by anyone using non-secure HTTP links by default. Non-secure HTTP requests can be restricted and all HTTP requests redirected to the secure HTTPS port. It is recommended to enforce HTTPS-only traffic.",
	"help_uri": "https://github.com/fugue/regula",
	"languages": ["json"],
	"severity": "high",
	"level": "error",
	"kind": "iac",
	"cwe": ["CWE-319"],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["arm", "azure", "app-service", "tls"],
}

findings contains finding if {
	some s in arm.resources("Microsoft.Web/sites")
	not object.get(s.resource.properties, "httpsOnly", false) == true
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("App Service site %q does not enforce HTTPS-only traffic.", [s.resource.name]),
		"artifact_uri": s.path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": 1,
		"snippet": sprintf("%s/%s", [s.resource.type, s.resource.name]),
	}
}
