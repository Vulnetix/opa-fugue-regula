# Adapted from https://github.com/fugue/regula (FG_R00486).
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.fugue_k8s_host_process_id_namespace

import rego.v1

import data.vulnetix.fugue.k8s

metadata := {
	"id": "FUGUE-K8S-HST-03",
	"name": "Pods should not share the host PID namespace",
	"description": "hostPID=true exposes host process information, including environment variables, to containers.",
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
	object.get(obj.pod_template.spec, "hostPID", false) == true
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("%s %q sets hostPID: true.", [obj.resource.kind, obj.resource.metadata.name]),
		"artifact_uri": obj.path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": 1,
		"snippet": sprintf("%s/%s", [obj.resource.kind, obj.resource.metadata.name]),
	}
}
