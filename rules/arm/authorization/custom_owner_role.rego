# Adapted from https://github.com/fugue/regula (FG_R00288).
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.fugue_arm_authorization_custom_owner_role

import rego.v1

import data.vulnetix.fugue.arm

metadata := {
	"id": "FUGUE-ARM-AUTH-01",
	"name": "Active Directory custom subscription owner roles should not be created",
	"description": "Subscription ownership should not include permission to create custom owner roles. The principle of least privilege should be followed and only necessary privileges should be assigned instead of allowing full administrative access.",
	"help_uri": "https://github.com/fugue/regula",
	"languages": ["json"],
	"severity": "medium",
	"level": "warning",
	"kind": "iac",
	"cwe": ["CWE-269"],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["arm", "azure", "authorization", "iam", "least-privilege"],
}

_is_subscription_scope(scope) if {
	scope == "/"
}

_is_subscription_scope(scope) if {
	regex.match(`^/subscriptions/[^/]+/?$`, lower(scope))
}

_is_subscription_scope(scope) if {
	regex.match(`^\[concat\('/subscriptions/',[^,]+\]$`, replace(lower(scope), " ", ""))
}

_is_subscription_scope(scope) if {
	replace(lower(scope), " ", "") == "[subscription().id]"
}

_as_array(x) := x if {
	is_array(x)
}

_as_array(x) := [x] if {
	not is_array(x)
}

_has_wildcard_action(res) if {
	some perm in object.get(res.properties, "permissions", [])
	acts := _as_array(object.get(perm, "actions", []))
	some a in acts
	a == "*"
}

_has_subscription_scope(res) if {
	some scope in object.get(res.properties, "assignableScopes", [])
	_is_subscription_scope(scope)
}

findings contains finding if {
	some r in arm.resources("Microsoft.Authorization/roledefinitions")
	_has_wildcard_action(r.resource)
	_has_subscription_scope(r.resource)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Custom role definition %q grants '*' at subscription scope.", [r.resource.name]),
		"artifact_uri": r.path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": 1,
		"snippet": sprintf("%s/%s", [r.resource.type, r.resource.name]),
	}
}
