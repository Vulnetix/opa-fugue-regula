# Adapted from https://github.com/fugue/regula (FG_R00288).
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.fugue_tf_az_auth_custom_owner_role

import rego.v1

import data.vulnetix.fugue.tf

metadata := {
	"id": "FUGUE-TF-AZ-AUTH-01",
	"name": "Active Directory custom subscription owner roles should not be created",
	"description": "Active Directory custom subscription owner roles should not be created. Subscription ownership should not include permission to create custom owner roles. The principle of least privilege should be followed and only necessary privileges should be assigned instead of allowing full administrative access.",
	"help_uri": "https://github.com/fugue/regula",
	"languages": ["terraform", "hcl"],
	"severity": "medium",
	"level": "warning",
	"kind": "iac",
	"cwe": ["CWE-269"],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["terraform", "azure", "authorization", "rbac"],
}

findings contains finding if {
	some r in tf.resources("azurerm_role_definition")
	_has_wildcard_action(r.block)
	_has_subscription_scope(r.block)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Role definition %q grants '*' action at subscription scope.", [r.name]),
		"artifact_uri": r.path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": 1,
		"snippet": sprintf("%s.%s", [r.type, r.name]),
	}
}

_has_wildcard_action(block) if {
	some p in tf.sub_blocks(block, "permissions")
	actions := tf.string_list_attr(p, "actions")
	"*" in actions
}

_has_subscription_scope(block) if {
	scopes := tf.string_list_attr(block, "assignable_scopes")
	some s in scopes
	_is_subscription_scope(s)
}

_is_subscription_scope(scope) if scope == "/"

_is_subscription_scope(scope) if {
	regex.match(`^/subscriptions/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/?$`, lower(scope))
}

_is_subscription_scope(scope) if startswith(scope, "data.azurerm_subscription.")
