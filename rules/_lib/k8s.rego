# Helper package — not a rule.
# Parses Kubernetes YAML manifests from input.file_contents into resource docs.

package vulnetix.fugue.k8s

import rego.v1

is_yaml(path) if endswith(lower(path), ".yaml")
is_yaml(path) if endswith(lower(path), ".yml")

# All k8s documents across all YAML files in input.file_contents.
# Each entry: {path, doc} where doc is the parsed YAML.
documents := [d |
	some path, content in input.file_contents
	is_yaml(path)
	some dstr in _split_docs_list(content)
	dstr != ""
	doc := yaml.unmarshal(dstr)
	is_object(doc)
	doc.apiVersion
	doc.kind
	d := {"path": path, "doc": doc}
]

# Split multi-document YAML by `---` separator.
_split_docs_list(content) := parts if {
	contains(content, "\n---\n")
	parts := split(content, "\n---\n")
}

_split_docs_list(content) := [content] if {
	not contains(content, "\n---\n")
}

# Resources of a particular kind.
resources(kind) := out if {
	out := [d |
		some d in documents
		d.doc.kind == kind
	]
}

# Documents that contain a pod template (Deployment, StatefulSet, DaemonSet,
# Job, CronJob, ReplicaSet, ReplicationController, Pod).
pod_template_kinds := {
	"Deployment",
	"StatefulSet",
	"DaemonSet",
	"Job",
	"CronJob",
	"ReplicaSet",
	"ReplicationController",
	"Pod",
}

resources_with_pod_templates := [r |
	some d in documents
	pod_template_kinds[d.doc.kind]
	pt := _pod_template(d.doc)
	r := {"path": d.path, "resource": d.doc, "pod_template": pt}
]

_pod_template(doc) := doc if doc.kind == "Pod"

_pod_template(doc) := doc.spec.template if {
	doc.kind != "Pod"
	doc.kind != "CronJob"
	doc.spec.template
}

_pod_template(doc) := doc.spec.jobTemplate.spec.template if {
	doc.kind == "CronJob"
}

# Containers (spec + initContainers) from a pod template.
containers(template) := out if {
	init := object.get(template.spec, "initContainers", [])
	main := object.get(template.spec, "containers", [])
	out := array.concat(main, init)
}

# Role-like resources (Role and ClusterRole).
roles := [d |
	some d in documents
	d.doc.kind in {"Role", "ClusterRole"}
]

# RoleBinding and ClusterRoleBinding.
role_bindings := [d |
	some d in documents
	d.doc.kind in {"RoleBinding", "ClusterRoleBinding"}
]

# Namespaced resources.
namespaced_kinds := {
	"ConfigMap",
	"CronJob",
	"DaemonSet",
	"Deployment",
	"Ingress",
	"Job",
	"Pod",
	"ReplicaSet",
	"ReplicationController",
	"Role",
	"RoleBinding",
	"Secret",
	"Service",
	"ServiceAccount",
	"StatefulSet",
}

namespaced_resources := [d |
	some d in documents
	namespaced_kinds[d.doc.kind]
]

# Resources with containers at spec.containers directly (Pods) or nested under
# spec.template.spec.containers.
resources_with_containers := [r |
	some obj in resources_with_pod_templates
	cs := containers(obj.pod_template)
	count(cs) > 0
	r := {"path": obj.path, "resource": obj.resource, "containers": cs}
]

# Added Linux capabilities for a container (returns [] if none).
added_capabilities(container) := out if {
	sc := object.get(container, "securityContext", {})
	caps := object.get(sc, "capabilities", {})
	out := object.get(caps, "add", [])
}

dropped_capabilities(container) := out if {
	sc := object.get(container, "securityContext", {})
	caps := object.get(sc, "capabilities", {})
	out := object.get(caps, "drop", [])
}

service_accounts := [d |
	some d in documents
	d.doc.kind == "ServiceAccount"
]

default_service_accounts := [d |
	some d in documents
	d.doc.kind == "ServiceAccount"
	d.doc.metadata.name == "default"
]

# Look up the Role/ClusterRole a binding references by name. Returns the first
# matching role document's `.doc` payload (or undefined if none).
role_from_binding(binding_entry) := role if {
	ref := binding_entry.doc.roleRef
	some r in roles
	r.doc.kind == ref.kind
	r.doc.metadata.name == ref.name
	role := r.doc
}
