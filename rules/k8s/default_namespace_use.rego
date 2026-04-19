# Adapted from https://github.com/fugue/regula (FG_R00497).
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.fugue_k8s_default_namespace_use

import rego.v1

import data.vulnetix.fugue.k8s

metadata := {
	"id": "FUGUE-K8S-NS-01",
	"name": "Do not deploy into the default namespace",
	"description": "Resources in the default namespace lack namespace-scoped isolation for RBAC, network policies and quotas.",
	"help_uri": "https://github.com/fugue/regula",
	"languages": ["yaml"],
	"severity": "low",
	"level": "note",
	"kind": "iac",
	"cwe": ["CWE-266"],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["kubernetes", "namespace", "hardening"],
}

findings contains finding if {
	some d in k8s.namespaced_resources
	_is_invalid(d.doc)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("%s %q is in the default namespace.", [d.doc.kind, d.doc.metadata.name]),
		"artifact_uri": d.path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": 1,
		"snippet": sprintf("%s/%s", [d.doc.kind, d.doc.metadata.name]),
	}
}

_is_invalid(resource) if {
	resource.metadata.namespace == "default"
	not resource.kind in {"ServiceAccount", "Service"}
}

_is_invalid(resource) if {
	resource.kind == "ServiceAccount"
	resource.metadata.namespace == "default"
	resource.metadata.name != "default"
}

_is_invalid(resource) if {
	resource.kind == "Service"
	resource.metadata.namespace == "default"
	resource.metadata.name != "kubernetes"
}
