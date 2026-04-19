# Adapted from https://github.com/fugue/regula (FG_R00007).
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.fugue_cfn_iam_policy

import rego.v1

import data.vulnetix.fugue.cfn

metadata := {
	"id": "FUGUE-CFN-IAM-02",
	"name": "IAM policies should not be attached to users",
	"description": "IAM policies should not be attached to users. Assign privileges at the group or role level to reduce access management complexity as the number of users grows.",
	"help_uri": "https://github.com/fugue/regula",
	"languages": ["yaml", "json"],
	"severity": "low",
	"level": "note",
	"kind": "iac",
	"cwe": ["CWE-269"],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["cloudformation", "aws", "iam"],
}

findings contains finding if {
	some r in cfn.resources("AWS::IAM::Policy")
	props := cfn.properties(r)
	count(props.Users) > 0
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("AWS::IAM::Policy %q is attached directly to one or more users.", [r.logical_id]),
		"artifact_uri": r.path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": 1,
		"snippet": sprintf("AWS::IAM::Policy/%s", [r.logical_id]),
	}
}

findings contains finding if {
	some r in cfn.resources("AWS::IAM::User")
	props := cfn.properties(r)
	count(props.Policies) > 0
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("AWS::IAM::User %q has inline Policies attached directly to the user.", [r.logical_id]),
		"artifact_uri": r.path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": 1,
		"snippet": sprintf("AWS::IAM::User/%s", [r.logical_id]),
	}
}
