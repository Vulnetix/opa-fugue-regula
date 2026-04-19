# Adapted from https://github.com/fugue/regula (FG_R00340).
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.fugue_tf_az_mon_log_profile_retention

import rego.v1

import data.vulnetix.fugue.tf

metadata := {
	"id": "FUGUE-TF-AZ-MON-04",
	"name": "Monitor 'Activity Log Retention' should be 365 days or greater",
	"description": "Monitor 'Activity Log Retention' should be 365 days or greater. A log profile controls how the activity log is exported and retained. Since the average time to detect a breach is 210 days, the activity log should be retained for 365 days or more in order to have time to respond to any incidents.",
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
	"tags": ["terraform", "azure", "monitor", "retention"],
}

findings contains finding if {
	some r in tf.resources("azurerm_monitor_log_profile")
	not _has_valid_retention(r.block)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Log profile %q does not retain activity logs for 365+ days (or indefinitely via days=0 & enabled=false).", [r.name]),
		"artifact_uri": r.path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": 1,
		"snippet": sprintf("%s.%s", [r.type, r.name]),
	}
}

_has_valid_retention(block) if {
	some rp in tf.sub_blocks(block, "retention_policy")
	tf.bool_attr(rp, "enabled") == true
	tf.number_attr(rp, "days") >= 365
}

_has_valid_retention(block) if {
	some rp in tf.sub_blocks(block, "retention_policy")
	tf.bool_attr(rp, "enabled") == false
	tf.number_attr(rp, "days") == 0
}
