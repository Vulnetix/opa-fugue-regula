# Adapted from https://github.com/fugue/regula (FG_R00286).
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.fugue_tf_az_net_flow_log_90d

import rego.v1

import data.vulnetix.fugue.tf

metadata := {
	"id": "FUGUE-TF-AZ-NET-02",
	"name": "Virtual Network security group flow log retention should be 90+ days",
	"description": "Virtual Network security group flow log retention period should be set to 90 days or greater. Flow logs enable capturing information about IP traffic flowing in and out of network security groups. Logs can be used to check for anomalies and give insight into suspected breaches.",
	"help_uri": "https://github.com/fugue/regula",
	"languages": ["terraform", "hcl"],
	"severity": "medium",
	"level": "warning",
	"kind": "iac",
	"cwe": ["CWE-778"],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["terraform", "azure", "network", "flow-log"],
}

findings contains finding if {
	some sg in tf.resources("azurerm_network_security_group")
	not _has_valid_flow_log(sg.name)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("NSG %q has no azurerm_network_watcher_flow_log with enabled retention_policy of 90+ days.", [sg.name]),
		"artifact_uri": sg.path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": 1,
		"snippet": sprintf("%s.%s", [sg.type, sg.name]),
	}
}

_has_valid_flow_log(sg_name) if {
	some fl in tf.resources("azurerm_network_watcher_flow_log")
	tf.references(fl.block, "azurerm_network_security_group", sg_name)
	some rp in tf.sub_blocks(fl.block, "retention_policy")
	tf.bool_attr(rp, "enabled") == true
	tf.number_attr(rp, "days") >= 90
}
