# Adapted from https://github.com/fugue/regula (FG_R00089).
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.fugue_cfn_vpc_default_security_group

import rego.v1

import data.vulnetix.fugue.cfn

metadata := {
	"id": "FUGUE-CFN-VPC-01",
	"name": "VPC default security group should restrict all traffic",
	"description": "VPC default security group should restrict all traffic. Restricting all traffic on default security groups encourages least-privilege SG design and mindful placement of AWS resources into explicit security groups.",
	"help_uri": "https://github.com/fugue/regula",
	"languages": ["yaml", "json"],
	"severity": "medium",
	"level": "warning",
	"kind": "iac",
	"cwe": ["CWE-284"],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["cloudformation", "aws", "vpc", "security-group"],
}

_targets_default_sg(rule_props) if {
	gid := rule_props.GroupId
	is_object(gid)
	getatt := gid["Fn::GetAtt"]
	is_array(getatt)
	getatt[1] == "DefaultSecurityGroup"
}

findings contains finding if {
	some r in cfn.resources("AWS::EC2::SecurityGroupIngress")
	props := cfn.properties(r)
	_targets_default_sg(props)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("SecurityGroupIngress %q adds rules to a VPC DefaultSecurityGroup.", [r.logical_id]),
		"artifact_uri": r.path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": 1,
		"snippet": sprintf("AWS::EC2::SecurityGroupIngress/%s", [r.logical_id]),
	}
}
