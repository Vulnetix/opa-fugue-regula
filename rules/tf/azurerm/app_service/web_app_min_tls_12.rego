# Adapted from https://github.com/fugue/regula (FG_R00347).
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.fugue_tf_az_as_min_tls

import rego.v1

import data.vulnetix.fugue.tf

metadata := {
	"id": "FUGUE-TF-AZ-AS-05",
	"name": "App Service web apps should have 'Minimum TLS Version' set to '1.2'",
	"description": "App Service web apps should have 'Minimum TLS Version' set to '1.2'. The TLS (Transport Layer Security) protocol secures transmission of data over the internet using standard encryption technology. Encryption should be set with the latest version of TLS. App service allows TLS 1.2 by default, which is the recommended TLS level by industry standards.",
	"help_uri": "https://github.com/fugue/regula",
	"languages": ["terraform", "hcl"],
	"severity": "medium",
	"level": "warning",
	"kind": "iac",
	"cwe": ["CWE-327"],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["terraform", "azure", "app-service", "tls"],
}

findings contains finding if {
	some r in tf.resources("azurerm_app_service")
	not _has_min_tls_12(r.block)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("App Service %q does not set site_config.min_tls_version to 1.2.", [r.name]),
		"artifact_uri": r.path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": 1,
		"snippet": sprintf("%s.%s", [r.type, r.name]),
	}
}

_has_min_tls_12(block) if {
	some sc in tf.sub_blocks(block, "site_config")
	tf.string_attr(sc, "min_tls_version") == "1.2"
}
