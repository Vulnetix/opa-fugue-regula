# Helper package — not a rule.
# Parses Azure Resource Manager (ARM) JSON templates from input.file_contents.

package vulnetix.fugue.arm

import rego.v1

_is_json(path) if endswith(lower(path), ".json")

# Parsed ARM templates. A file counts as an ARM template when it has the ARM
# `$schema` marker or the top-level resources[] array with type+apiVersion.
templates := [t |
	some path, content in input.file_contents
	_is_json(path)
	parsed := json.unmarshal(content)
	is_object(parsed)
	_is_arm(parsed)
	t := {"path": path, "template": parsed}
]

_is_arm(parsed) if {
	schema := object.get(parsed, "$schema", "")
	contains(lower(schema), "deploymenttemplate.json")
}

_is_arm(parsed) if {
	rs := object.get(parsed, "resources", [])
	is_array(rs)
	count(rs) > 0
	r := rs[0]
	r.type
	r.apiVersion
}

# All ARM resources: top-level + one level of nested child resources.
# Each entry: {path, resource}.
all_resources := out if {
	out := [r |
		some t in templates
		some raw in _top_and_nested(t.template)
		r := {"path": t.path, "resource": raw}
	]
}

_top_and_nested(template) := out if {
	top := [r |
		some r in object.get(template, "resources", [])
		is_object(r)
	]
	nested := [c |
		some r in top
		some c in object.get(r, "resources", [])
		is_object(c)
	]
	out := array.concat(top, nested)
}

resources(type) := out if {
	out := [r | some r in all_resources; r.resource.type == type]
}
