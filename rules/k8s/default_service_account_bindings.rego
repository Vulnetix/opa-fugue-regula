# Adapted from https://github.com/fugue/regula (FG_R00498).
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.fugue_k8s_default_service_account_bindings

import rego.v1

import data.vulnetix.fugue.k8s

metadata := {
	"id": "FUGUE-K8S-RBAC-04",
	"name": "Do not bind roles to the default service account",
	"description": "Each workload should use a dedicated ServiceAccount. Binding roles to the 'default' SA grants those privileges to every pod that does not override the SA.",
	"help_uri": "https://github.com/fugue/regula",
	"languages": ["yaml"],
	"severity": "medium",
	"level": "warning",
	"kind": "iac",
	"cwe": ["CWE-269"],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["kubernetes", "rbac", "service-account"],
}

findings contains finding if {
	some binding in k8s.role_bindings
	_binds_default_sa(binding.doc)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("%s %q binds the default ServiceAccount.", [binding.doc.kind, binding.doc.metadata.name]),
		"artifact_uri": binding.path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": 1,
		"snippet": sprintf("%s/%s", [binding.doc.kind, binding.doc.metadata.name]),
	}
}

_binds_default_sa(binding) if {
	some s in binding.subjects
	s.kind == "ServiceAccount"
	s.name == "default"
}
