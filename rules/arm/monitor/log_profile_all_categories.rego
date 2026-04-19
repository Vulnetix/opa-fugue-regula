# Adapted from https://github.com/fugue/regula (FG_R00341).
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.fugue_arm_monitor_log_profile_all_categories

import rego.v1

import data.vulnetix.fugue.arm

metadata := {
	"id": "FUGUE-ARM-MON-02",
	"name": "Monitor audit profile should log all activities",
	"description": "The log profile should be configured to export all activities from the control/management plane. A log profile controls how the activity log is exported. Configuring the log profile to collect logs for the categories \"write\", \"delete\" and \"action\" ensures that all the control/management plane activities performed on the subscription are exported.",
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
	"tags": ["arm", "azure", "monitor", "logging"],
}

_required := {"write", "delete", "action"}

_has_all_categories(r) if {
	cats := {lower(c) | some c in object.get(r.resource.properties, "categories", [])}
	count(_required - cats) == 0
}

findings contains finding if {
	some r in arm.resources("Microsoft.Insights/logprofiles")
	not _has_all_categories(r)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Log profile %q does not include all of write/delete/action categories.", [r.resource.name]),
		"artifact_uri": r.path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": 1,
		"snippet": sprintf("%s/%s", [r.resource.type, r.resource.name]),
	}
}
