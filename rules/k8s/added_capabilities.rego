# Adapted from https://github.com/fugue/regula (FG_R00492).
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.fugue_k8s_added_capabilities

import rego.v1

import data.vulnetix.fugue.k8s

metadata := {
	"id": "FUGUE-K8S-CAP-01",
	"name": "Containers should not add Linux capabilities",
	"description": "Adding capabilities beyond the default set expands the attack surface for container breakout.",
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
	"tags": ["kubernetes", "capabilities", "hardening"],
}

findings contains finding if {
	some obj in k8s.resources_with_containers
	some c in obj.containers
	count(k8s.added_capabilities(c)) > 0
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("%s %q adds Linux capabilities to container %q.", [obj.resource.kind, obj.resource.metadata.name, object.get(c, "name", "<unnamed>")]),
		"artifact_uri": obj.path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": 1,
		"snippet": sprintf("%s/%s", [obj.resource.kind, obj.resource.metadata.name]),
	}
}
