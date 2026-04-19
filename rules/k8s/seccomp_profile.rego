# Adapted from https://github.com/fugue/regula (FG_R00495).
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.fugue_k8s_seccomp_profile

import rego.v1

import data.vulnetix.fugue.k8s

metadata := {
	"id": "FUGUE-K8S-SEC-04",
	"name": "Pods should set a seccomp profile",
	"description": "Pod metadata annotation 'seccomp.security.alpha.kubernetes.io/pod' should be set to 'runtime/default' or 'docker/default'.",
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
	"tags": ["kubernetes", "hardening", "seccomp"],
}

_approved := {"docker/default", "runtime/default"}

findings contains finding if {
	some obj in k8s.resources_with_pod_templates
	not _seccomp_set(obj.pod_template)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("%s %q does not set an approved seccomp profile.", [obj.resource.kind, obj.resource.metadata.name]),
		"artifact_uri": obj.path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": 1,
		"snippet": sprintf("%s/%s", [obj.resource.kind, obj.resource.metadata.name]),
	}
}

_seccomp_set(template) if {
	annotations := object.get(object.get(template, "metadata", {}), "annotations", {})
	profile := annotations["seccomp.security.alpha.kubernetes.io/pod"]
	profile in _approved
}
