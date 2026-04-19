# Adapted from https://github.com/fugue/regula (FG_R00487).
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.fugue_k8s_host_ipc_namespace

import rego.v1

import data.vulnetix.fugue.k8s

metadata := {
	"id": "FUGUE-K8S-HST-01",
	"name": "Pods should not share the host IPC namespace",
	"description": "hostIPC=true lets the container access host IPC mechanisms, breaking isolation.",
	"help_uri": "https://github.com/fugue/regula",
	"languages": ["yaml"],
	"severity": "medium",
	"level": "warning",
	"kind": "iac",
	"cwe": ["CWE-668"],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["kubernetes", "hardening", "isolation"],
}

findings contains finding if {
	some obj in k8s.resources_with_pod_templates
	object.get(obj.pod_template.spec, "hostIPC", false) == true
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("%s %q sets hostIPC: true.", [obj.resource.kind, obj.resource.metadata.name]),
		"artifact_uri": obj.path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": 1,
		"snippet": sprintf("%s/%s", [obj.resource.kind, obj.resource.metadata.name]),
	}
}
