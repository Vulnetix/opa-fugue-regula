# Adapted from https://github.com/fugue/regula (FG_R00340).
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.fugue_arm_monitor_log_profile_retention

import rego.v1

import data.vulnetix.fugue.arm

metadata := {
	"id": "FUGUE-ARM-MON-04",
	"name": "Monitor 'Activity Log Retention' should be 365 days or greater",
	"description": "A log profile controls how the activity log is exported and retained. Since the average time to detect a breach is 210 days, the activity log should be retained for 365 days or more in order to have time to respond to any incidents.",
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
	"tags": ["arm", "azure", "monitor", "logging", "retention"],
}

_retention_ok(r) if {
	r.resource.properties.retentionPolicy.enabled == true
	r.resource.properties.retentionPolicy.days >= 365
}

_retention_ok(r) if {
	r.resource.properties.retentionPolicy.enabled == true
	r.resource.properties.retentionPolicy.days == 0
}

findings contains finding if {
	some r in arm.resources("Microsoft.Insights/logprofiles")
	not _retention_ok(r)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Log profile %q has retention less than 365 days.", [r.resource.name]),
		"artifact_uri": r.path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": 1,
		"snippet": sprintf("%s/%s", [r.resource.type, r.resource.name]),
	}
}
