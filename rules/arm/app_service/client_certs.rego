# Adapted from https://github.com/fugue/regula (FG_R00348).
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.fugue_arm_app_service_client_certs

import rego.v1

import data.vulnetix.fugue.arm

metadata := {
	"id": "FUGUE-ARM-AS-02",
	"name": "App Service web apps should have 'Incoming client certificates' enabled",
	"description": "Client certificates allow for the app to request a certificate for incoming requests. Only clients that have a valid certificate will be able to reach the app.",
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
	"tags": ["arm", "azure", "app-service", "client-cert"],
}

findings contains finding if {
	some s in arm.resources("Microsoft.Web/sites")
	not object.get(s.resource.properties, "clientCertEnabled", false) == true
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("App Service site %q does not have clientCertEnabled=true.", [s.resource.name]),
		"artifact_uri": s.path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": 1,
		"snippet": sprintf("%s/%s", [s.resource.type, s.resource.name]),
	}
}
