# Helper package — not a rule.
# Parses CloudFormation YAML/JSON templates from input.file_contents.

package vulnetix.fugue.cfn

import rego.v1

_is_yaml(path) if endswith(lower(path), ".yaml")
_is_yaml(path) if endswith(lower(path), ".yml")

_is_json(path) if endswith(lower(path), ".json")

# Parsed CFN templates. Each entry: {path, template}. A file counts as a CFN
# template when it has a top-level Resources map.
templates := [t |
	some path, content in input.file_contents
	template := _parse(path, content)
	is_object(template)
	is_object(object.get(template, "Resources", null))
	t := {"path": path, "template": template}
]

_parse(path, content) := parsed if {
	_is_yaml(path)
	parsed := yaml.unmarshal(content)
}

_parse(path, content) := parsed if {
	_is_json(path)
	parsed := json.unmarshal(content)
}

# All resources of a given Type. Each entry: {path, logical_id, resource}.
resources(type) := out if {
	out := [r |
		some t in templates
		some logical_id, resource in t.template.Resources
		is_object(resource)
		resource.Type == type
		r := {"path": t.path, "logical_id": logical_id, "resource": resource}
	]
}

# Convenient accessor for Properties (returns {} if absent).
properties(resource) := object.get(resource.resource, "Properties", {})
