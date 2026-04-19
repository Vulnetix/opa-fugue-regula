# Adapted from https://github.com/fugue/regula (FG_R00481).
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.fugue_k8s_role_wildcards

import rego.v1

import data.vulnetix.fugue.k8s

metadata := {
	"id": "FUGUE-K8S-RBAC-05",
	"name": "Roles should not use wildcard entries",
	"description": "Wildcard apiGroups/resources/verbs in Role or ClusterRule violate least privilege by matching everything.",
	"help_uri": "https://github.com/fugue/regula",
	"languages": ["yaml"],
	"severity": "high",
	"level": "error",
	"kind": "iac",
	"cwe": ["CWE-269"],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["kubernetes", "rbac", "least-privilege"],
}

findings contains finding if {
	some role in k8s.roles
	_has_wildcard(role.doc)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("%s %q uses a wildcard in apiGroups/resources/verbs.", [role.doc.kind, role.doc.metadata.name]),
		"artifact_uri": role.path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": 1,
		"snippet": sprintf("%s/%s", [role.doc.kind, role.doc.metadata.name]),
	}
}

_has_wildcard(role) if {
	some r in role.rules
	"*" in object.get(r, "apiGroups", [])
}

_has_wildcard(role) if {
	some r in role.rules
	"*" in object.get(r, "resources", [])
}

_has_wildcard(role) if {
	some r in role.rules
	"*" in object.get(r, "verbs", [])
}
