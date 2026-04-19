# Adapted from https://github.com/fugue/regula (FG_R00348).
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.fugue_tf_az_as_client_certs

import rego.v1

import data.vulnetix.fugue.tf

metadata := {
	"id": "FUGUE-TF-AZ-AS-04",
	"name": "App Service web apps should have 'Incoming client certificates' enabled",
	"description": "App Service web apps should have 'Incoming client certificates' enabled. Client certificates allow for the app to request a certificate for incoming requests. Only clients that have a valid certificate will be able to reach the app.",
	"help_uri": "https://github.com/fugue/regula",
	"languages": ["terraform", "hcl"],
	"severity": "medium",
	"level": "warning",
	"kind": "iac",
	"cwe": ["CWE-295"],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["terraform", "azure", "app-service", "client-cert"],
}

findings contains finding if {
	some r in tf.resources("azurerm_app_service")
	not tf.bool_attr(r.block, "client_cert_enabled") == true
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("App Service %q does not have client_cert_enabled = true.", [r.name]),
		"artifact_uri": r.path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": 1,
		"snippet": sprintf("%s.%s", [r.type, r.name]),
	}
}
