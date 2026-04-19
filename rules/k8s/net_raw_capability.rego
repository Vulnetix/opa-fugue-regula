# Adapted from https://github.com/fugue/regula (FG_R00491).
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.fugue_k8s_net_raw_capability

import rego.v1

import data.vulnetix.fugue.k8s

metadata := {
	"id": "FUGUE-K8S-CAP-03",
	"name": "Containers should drop the NET_RAW capability",
	"description": "NET_RAW allows crafting arbitrary packets and spoofed traffic. Drop NET_RAW explicitly unless absolutely required.",
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

_drop_accepted := {"NET_RAW", "all", "ALL"}

findings contains finding if {
	some obj in k8s.resources_with_containers
	some c in obj.containers
	not _drops_net_raw(c)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("%s %q does not drop NET_RAW on container %q.", [obj.resource.kind, obj.resource.metadata.name, object.get(c, "name", "<unnamed>")]),
		"artifact_uri": obj.path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": 1,
		"snippet": sprintf("%s/%s", [obj.resource.kind, obj.resource.metadata.name]),
	}
}

_drops_net_raw(container) if {
	dropped := {d | some d in k8s.dropped_capabilities(container)}
	count(dropped & _drop_accepted) >= 1
}
