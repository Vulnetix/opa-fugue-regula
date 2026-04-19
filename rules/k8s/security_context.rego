# Adapted from https://github.com/fugue/regula (FG_R00496).
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.fugue_k8s_security_context

import rego.v1

import data.vulnetix.fugue.k8s

metadata := {
	"id": "FUGUE-K8S-SEC-06",
	"name": "Pods should set a securityContext",
	"description": "A pod-level or container-level securityContext must be set to configure access control, capabilities and privileges.",
	"help_uri": "https://github.com/fugue/regula",
	"languages": ["yaml"],
	"severity": "medium",
	"level": "warning",
	"kind": "iac",
	"cwe": ["CWE-250"],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["kubernetes", "hardening", "security-context"],
}

findings contains finding if {
	some obj in k8s.resources_with_pod_templates
	containers := object.get(obj.pod_template.spec, "containers", [])
	count(containers) > 0
	not _has_pod_sc(obj.pod_template)
	not _all_containers_have_sc(containers)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("%s %q does not set a pod-level or per-container securityContext.", [obj.resource.kind, obj.resource.metadata.name]),
		"artifact_uri": obj.path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": 1,
		"snippet": sprintf("%s/%s", [obj.resource.kind, obj.resource.metadata.name]),
	}
}

_has_pod_sc(template) if {
	sc := object.get(template.spec, "securityContext", {})
	count(sc) > 0
}

_all_containers_have_sc(containers) if {
	count(containers) > 0
	every c in containers {
		sc := object.get(c, "securityContext", {})
		count(sc) > 0
	}
}
