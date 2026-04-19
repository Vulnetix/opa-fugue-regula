# Adapted from https://github.com/fugue/regula (FG_R00489).
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.fugue_k8s_allow_privilege_escalation

import rego.v1

import data.vulnetix.fugue.k8s

metadata := {
	"id": "FUGUE-K8S-SEC-01",
	"name": "Containers should not allow privilege escalation",
	"description": "securityContext.allowPrivilegeEscalation must be false to prevent a process from gaining more privileges than its parent.",
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
	"tags": ["kubernetes", "hardening", "privilege-escalation"],
}

findings contains finding if {
	some obj in k8s.resources_with_pod_templates
	containers := object.get(obj.pod_template.spec, "containers", [])
	count(containers) > 0
	some c in containers
	object.get(object.get(c, "securityContext", {}), "allowPrivilegeEscalation", false) == true
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("%s %q allows privilege escalation.", [obj.resource.kind, obj.resource.metadata.name]),
		"artifact_uri": obj.path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": 1,
		"snippet": sprintf("%s/%s", [obj.resource.kind, obj.resource.metadata.name]),
	}
}
