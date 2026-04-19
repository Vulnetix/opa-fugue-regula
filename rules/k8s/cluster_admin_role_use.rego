# Adapted from https://github.com/fugue/regula (FG_R00479).
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.fugue_k8s_cluster_admin_role_use

import rego.v1

import data.vulnetix.fugue.k8s

metadata := {
	"id": "FUGUE-K8S-RBAC-03",
	"name": "The cluster-admin role should not be bound",
	"description": "cluster-admin grants super-user access. Binding it to subjects is rarely justified and should be flagged for review.",
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
	some binding in k8s.role_bindings
	binding.doc.roleRef.name == "cluster-admin"
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("%s %q binds the cluster-admin role.", [binding.doc.kind, binding.doc.metadata.name]),
		"artifact_uri": binding.path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": 1,
		"snippet": sprintf("%s/%s", [binding.doc.kind, binding.doc.metadata.name]),
	}
}
