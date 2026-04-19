# Adapted from https://github.com/fugue/regula (FG_R00490).
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.fugue_k8s_root_containers

import rego.v1

import data.vulnetix.fugue.k8s

metadata := {
	"id": "FUGUE-K8S-SEC-03",
	"name": "Containers must not run as root",
	"description": "A container is considered able to run as root unless (runAsNonRoot=true) OR (runAsUser > 0). The pod-level securityContext applies if the container does not override.",
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
	"tags": ["kubernetes", "hardening", "root"],
}

findings contains finding if {
	some obj in k8s.resources_with_pod_templates
	containers := object.get(obj.pod_template.spec, "containers", [])
	count(containers) > 0
	some c in containers
	_can_run_as_root(obj.pod_template.spec, c)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("%s %q can run container %q as root.", [obj.resource.kind, obj.resource.metadata.name, object.get(c, "name", "<unnamed>")]),
		"artifact_uri": obj.path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": 1,
		"snippet": sprintf("%s/%s", [obj.resource.kind, obj.resource.metadata.name]),
	}
}

_can_run_as_root(spec, container) if {
	_run_as_non_root(spec, container) != true
	uid := _run_as_user(spec, container)
	uid in {0, "unknown"}
}

_run_as_non_root(spec, container) := val if {
	sc := object.get(container, "securityContext", {})
	val := sc.runAsNonRoot
} else := val if {
	sc := object.get(spec, "securityContext", {})
	val := sc.runAsNonRoot
} else := false

_run_as_user(spec, container) := val if {
	sc := object.get(container, "securityContext", {})
	val := sc.runAsUser
} else := val if {
	sc := object.get(spec, "securityContext", {})
	val := sc.runAsUser
} else := "unknown"
