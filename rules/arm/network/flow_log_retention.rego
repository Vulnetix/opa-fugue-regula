# Adapted from https://github.com/fugue/regula (FG_R00286).
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.fugue_arm_network_flow_log_retention

import rego.v1

import data.vulnetix.fugue.arm

metadata := {
	"id": "FUGUE-ARM-NET-02",
	"name": "Virtual Network security group flow log retention period should be set to 90 days or greater",
	"description": "Flow logs enable capturing information about IP traffic flowing in and out of network security groups. Logs can be used to check for anomalies and give insight into suspected breaches.",
	"help_uri": "https://github.com/fugue/regula",
	"languages": ["json"],
	"severity": "medium",
	"level": "warning",
	"kind": "iac",
	"cwe": ["CWE-778"],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["arm", "azure", "network", "logging", "retention"],
}

_flow_log_has_retention(fl) if {
	fl.properties.retentionPolicy.enabled == true
	fl.properties.retentionPolicy.days >= 90
}

# Match flow logs whose properties.targetResourceId references the NSG by name.
_matching_flow_logs(nsg_name) := [fl.resource |
	some fl in arm.resources("Microsoft.Network/networkWatchers/flowLogs")
	target := object.get(fl.resource.properties, "targetResourceId", "")
	contains(lower(target), lower(sprintf("networkSecurityGroups/%s", [nsg_name])))
]

_nsg_ok(nsg_name) if {
	logs := _matching_flow_logs(nsg_name)
	count(logs) > 0
	every fl in logs {
		_flow_log_has_retention(fl)
	}
}

findings contains finding if {
	some nsg in arm.resources("Microsoft.Network/networkSecurityGroups")
	not _nsg_ok(nsg.resource.name)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("NSG %q has missing or insufficient (<90d) flow log retention.", [nsg.resource.name]),
		"artifact_uri": nsg.path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": 1,
		"snippet": sprintf("%s/%s", [nsg.resource.type, nsg.resource.name]),
	}
}
