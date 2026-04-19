# Adapted from https://github.com/fugue/regula (FG_R00480).
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.fugue_k8s_access_to_secrets

import rego.v1

import data.vulnetix.fugue.k8s

metadata := {
	"id": "FUGUE-K8S-RBAC-02",
	"name": "Roles should not grant get/list/watch on secrets",
	"description": "RBAC grants of get/list/watch on 'secrets' expose credentials stored as Kubernetes Secrets.",
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
	"tags": ["kubernetes", "rbac", "secrets"],
}

_match_verbs := {"get", "list", "watch"}

findings contains finding if {
	some binding in k8s.role_bindings
	role := k8s.role_from_binding(binding)
	_is_invalid_role(role)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("%s %q binds a role that grants get/list/watch on secrets.", [binding.doc.kind, binding.doc.metadata.name]),
		"artifact_uri": binding.path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": 1,
		"snippet": sprintf("%s/%s", [binding.doc.kind, binding.doc.metadata.name]),
	}
}

_is_invalid_role(role) if {
	some r in role.rules
	"secrets" in r.resources
	some v in r.verbs
	v in _match_verbs
}
