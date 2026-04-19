# Adapted from https://github.com/fugue/regula (FG_R00484).
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.fugue_k8s_service_account_tokens

import rego.v1

import data.vulnetix.fugue.k8s

metadata := {
	"id": "FUGUE-K8S-SA-02",
	"name": "Pods/ServiceAccounts should disable automountServiceAccountToken",
	"description": "Workloads that do not need to talk to the Kubernetes API should set automountServiceAccountToken: false.",
	"help_uri": "https://github.com/fugue/regula",
	"languages": ["yaml"],
	"severity": "medium",
	"level": "warning",
	"kind": "iac",
	"cwe": ["CWE-522"],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["kubernetes", "service-account", "hardening"],
}

findings contains finding if {
	some obj in k8s.resources_with_pod_templates
	containers := object.get(obj.pod_template.spec, "containers", [])
	count(containers) > 0
	object.get(obj.pod_template.spec, "automountServiceAccountToken", true) != false
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("%s %q does not disable automountServiceAccountToken.", [obj.resource.kind, obj.resource.metadata.name]),
		"artifact_uri": obj.path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": 1,
		"snippet": sprintf("%s/%s", [obj.resource.kind, obj.resource.metadata.name]),
	}
}

findings contains finding if {
	some sa in k8s.service_accounts
	object.get(sa.doc, "automountServiceAccountToken", true) != false
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("ServiceAccount %q does not disable automountServiceAccountToken.", [sa.doc.metadata.name]),
		"artifact_uri": sa.path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": 1,
		"snippet": sprintf("ServiceAccount/%s", [sa.doc.metadata.name]),
	}
}
