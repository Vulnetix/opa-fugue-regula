# Adapted from https://github.com/fugue/regula (FG_R00092).
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.fugue_cfn_iam_admin_policy

import rego.v1

import data.vulnetix.fugue.cfn

metadata := {
	"id": "FUGUE-CFN-IAM-01",
	"name": "IAM policies should not have full \"*:*\" privileges",
	"description": "IAM policies should not have full \"*:*\" administrative privileges. Policies should start with a minimum set of permissions rather than wildcard admin access.",
	"help_uri": "https://github.com/fugue/regula",
	"languages": ["yaml", "json"],
	"severity": "high",
	"level": "error",
	"kind": "iac",
	"cwe": ["CWE-269"],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["cloudformation", "aws", "iam", "privilege-escalation"],
}

_as_array(x) := [x] if not is_array(x)
_as_array(x) := x if is_array(x)

_is_wildcard_policy(doc) if {
	some statement in _as_array(doc.Statement)
	statement.Effect == "Allow"
	some resource in _as_array(statement.Resource)
	resource == "*"
	some action in _as_array(statement.Action)
	action == "*"
}

_policy_docs(r, type_name) := docs if {
	type_name == "AWS::IAM::Policy"
	props := cfn.properties(r)
	docs := [props.PolicyDocument]
}

_policy_docs(r, type_name) := docs if {
	type_name != "AWS::IAM::Policy"
	props := cfn.properties(r)
	docs := [doc |
		some p in props.Policies
		doc := p.PolicyDocument
	]
}

findings contains finding if {
	some type_name in ["AWS::IAM::Policy", "AWS::IAM::Role", "AWS::IAM::User", "AWS::IAM::Group"]
	some r in cfn.resources(type_name)
	docs := _policy_docs(r, type_name)
	some doc in docs
	_is_wildcard_policy(doc)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("%s %q grants wildcard Action:'*' on Resource:'*'.", [type_name, r.logical_id]),
		"artifact_uri": r.path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": 1,
		"snippet": sprintf("%s/%s", [type_name, r.logical_id]),
	}
}
