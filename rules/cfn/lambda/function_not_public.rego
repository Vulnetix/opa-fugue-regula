# Adapted from https://github.com/fugue/regula (FG_R00276).
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.fugue_cfn_lambda_function_not_public

import rego.v1

import data.vulnetix.fugue.cfn

metadata := {
	"id": "FUGUE-CFN-LMB-01",
	"name": "Lambda function policies should not allow global access",
	"description": "Lambda function policies should not allow global access. Publicly accessible lambda functions may be invokable by anyone and could drive up costs, disrupt services, or leak data.",
	"help_uri": "https://github.com/fugue/regula",
	"languages": ["yaml", "json"],
	"severity": "high",
	"level": "error",
	"kind": "iac",
	"cwe": ["CWE-284"],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["cloudformation", "aws", "lambda", "public-access"],
}

# Match Permission.FunctionName to a Function by Ref to logical id or by exact FunctionName.
_permission_targets(perm_props, function_entry) if {
	fn := perm_props.FunctionName
	is_object(fn)
	fn.Ref == function_entry.logical_id
}

_permission_targets(perm_props, function_entry) if {
	fn := perm_props.FunctionName
	fn_props := cfn.properties(function_entry)
	fn == fn_props.FunctionName
}

_public_permission_for(function_entry) if {
	some p in cfn.resources("AWS::Lambda::Permission")
	pp := cfn.properties(p)
	pp.Principal == "*"
	_permission_targets(pp, function_entry)
}

findings contains finding if {
	some type_name in ["AWS::Lambda::Function", "AWS::Serverless::Function"]
	some r in cfn.resources(type_name)
	_public_permission_for(r)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("%s %q has an AWS::Lambda::Permission granting Principal '*' (public access).", [type_name, r.logical_id]),
		"artifact_uri": r.path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": 1,
		"snippet": sprintf("%s/%s", [type_name, r.logical_id]),
	}
}
