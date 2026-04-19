# Adapted from https://github.com/fugue/regula (FG_R00482).
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.fugue_k8s_access_to_create_pods

import rego.v1

import data.vulnetix.fugue.k8s

metadata := {
	"id": "FUGUE-K8S-RBAC-01",
	"name": "Roles should not grant 'create' permissions for pods",
	"description": "RBAC Roles and ClusterRoles that grant 'create' on 'pods' enable privilege escalation via pod creation (attacker-controlled service accounts, host mounts, etc.).",
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
	"tags": ["kubernetes", "rbac", "privilege-escalation"],
}

findings contains finding if {
	some role in k8s.roles
	_is_invalid(role.doc)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("%s %q grants 'create' on 'pods'.", [role.doc.kind, role.doc.metadata.name]),
		"artifact_uri": role.path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": 1,
		"snippet": sprintf("%s/%s", [role.doc.kind, role.doc.metadata.name]),
	}
}

_is_invalid(role) if {
	some r in role.rules
	"pods" in r.resources
	"create" in r.verbs
}
