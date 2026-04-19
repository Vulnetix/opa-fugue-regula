# Adapted from https://github.com/fugue/regula (FG_R00054).
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.fugue_cfn_vpc_flow_logging_enabled

import rego.v1

import data.vulnetix.fugue.cfn

metadata := {
	"id": "FUGUE-CFN-VPC-02",
	"name": "VPC flow logging should be enabled",
	"description": "VPC flow logging should be enabled. AWS VPC Flow Logs provide visibility into network traffic that traverses the VPC and can be used to detect anomalous traffic.",
	"help_uri": "https://github.com/fugue/regula",
	"languages": ["yaml", "json"],
	"severity": "medium",
	"level": "warning",
	"kind": "iac",
	"cwe": ["CWE-778"],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["cloudformation", "aws", "vpc", "logging"],
}

_vpc_has_flow_log(vpc_entry) if {
	some fl in cfn.resources("AWS::EC2::FlowLog")
	fp := cfn.properties(fl)
	fp.ResourceType == "VPC"
	_flowlog_targets_vpc(fp.ResourceId, vpc_entry)
}

_flowlog_targets_vpc(rid, vpc_entry) if {
	rid == vpc_entry.logical_id
}

_flowlog_targets_vpc(rid, vpc_entry) if {
	is_object(rid)
	rid.Ref == vpc_entry.logical_id
}

findings contains finding if {
	some r in cfn.resources("AWS::EC2::VPC")
	not _vpc_has_flow_log(r)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("VPC %q has no AWS::EC2::FlowLog targeting it.", [r.logical_id]),
		"artifact_uri": r.path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": 1,
		"snippet": sprintf("AWS::EC2::VPC/%s", [r.logical_id]),
	}
}
