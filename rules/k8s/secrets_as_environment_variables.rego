# Adapted from https://github.com/fugue/regula (FG_R00494).
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.fugue_k8s_secrets_as_environment_variables

import rego.v1

import data.vulnetix.fugue.k8s

metadata := {
	"id": "FUGUE-K8S-SEC-05",
	"name": "Secrets should not be exposed as environment variables",
	"description": "Prefer volume-mounted secrets over env var injection. Environment variables can leak via logging and process enumeration.",
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
	"tags": ["kubernetes", "secrets", "hardening"],
}

findings contains finding if {
	some obj in k8s.resources_with_pod_templates
	containers := object.get(obj.pod_template.spec, "containers", [])
	count(containers) > 0
	some c in containers
	some e in object.get(c, "env", [])
	object.get(object.get(e, "valueFrom", {}), "secretKeyRef", {}).name
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("%s %q injects secrets via environment variables.", [obj.resource.kind, obj.resource.metadata.name]),
		"artifact_uri": obj.path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": 1,
		"snippet": sprintf("%s/%s", [obj.resource.kind, obj.resource.metadata.name]),
	}
}
