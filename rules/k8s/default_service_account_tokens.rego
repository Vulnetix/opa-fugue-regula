# Adapted from https://github.com/fugue/regula (FG_R00483).
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.fugue_k8s_default_service_account_tokens

import rego.v1

import data.vulnetix.fugue.k8s

metadata := {
	"id": "FUGUE-K8S-SA-01",
	"name": "Default ServiceAccount must disable automountServiceAccountToken",
	"description": "The default ServiceAccount should not automount API credentials. Set automountServiceAccountToken: false on the default SA in each namespace.",
	"help_uri": "https://github.com/fugue/regula",
	"languages": ["yaml"],
	"severity": "medium",
	"level": "warning",
	"kind": "iac",
	"cwe": ["CWE-522"],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["kubernetes", "service-account", "hardening"],
}

findings contains finding if {
	some sa in k8s.default_service_accounts
	object.get(sa.doc, "automountServiceAccountToken", true) != false
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Default ServiceAccount in namespace %q does not disable automountServiceAccountToken.", [object.get(sa.doc.metadata, "namespace", "default")]),
		"artifact_uri": sa.path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": 1,
		"snippet": sprintf("ServiceAccount/%s", [sa.doc.metadata.name]),
	}
}
