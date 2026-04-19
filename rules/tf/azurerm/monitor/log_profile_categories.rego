# Adapted from https://github.com/fugue/regula (FG_R00341).
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.fugue_tf_az_mon_log_profile_categories

import rego.v1

import data.vulnetix.fugue.tf

metadata := {
	"id": "FUGUE-TF-AZ-MON-02",
	"name": "Monitor audit profile should log all activities",
	"description": "Monitor audit profile should log all activities. The log profile should be configured to export all activities from the control/management plane. A log profile controls how the activity log is exported. Configuring the log profile to collect logs for the categories 'write', 'delete' and 'action' ensures that all the control/management plane activities performed on the subscription are exported.",
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
	"tags": ["terraform", "azure", "monitor", "log-profile"],
}

findings contains finding if {
	some r in tf.resources("azurerm_monitor_log_profile")
	not _has_all_categories(r.block)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Log profile %q is missing required categories (write, delete, action).", [r.name]),
		"artifact_uri": r.path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": 1,
		"snippet": sprintf("%s.%s", [r.type, r.name]),
	}
}

_has_all_categories(block) if {
	cats := tf.string_list_attr(block, "categories")
	lowers := {lower(c) | some c in cats}
	"write" in lowers
	"delete" in lowers
	"action" in lowers
}
