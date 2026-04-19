# Adapted from https://github.com/fugue/regula (FG_R00485).
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.fugue_k8s_privileged_containers

import rego.v1

import data.vulnetix.fugue.k8s

metadata := {
	"id": "FUGUE-K8S-SEC-02",
	"name": "Containers must not run privileged",
	"description": "securityContext.privileged=true grants host-level capabilities, giving the container near-full access to the node.",
	"help_uri": "https://github.com/fugue/regula",
	"languages": ["yaml"],
	"severity": "high",
	"level": "error",
	"kind": "iac",
	"cwe": ["CWE-250"],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["kubernetes", "hardening", "privileged"],
}

findings contains finding if {
	some obj in k8s.resources_with_pod_templates
	containers := object.get(obj.pod_template.spec, "containers", [])
	count(containers) > 0
	some c in containers
	object.get(object.get(c, "securityContext", {}), "privileged", false) == true
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("%s %q runs a privileged container.", [obj.resource.kind, obj.resource.metadata.name]),
		"artifact_uri": obj.path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": 1,
		"snippet": sprintf("%s/%s", [obj.resource.kind, obj.resource.metadata.name]),
	}
}
