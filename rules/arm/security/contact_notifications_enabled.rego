# Adapted from https://github.com/fugue/regula (FG_R00468).
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.fugue_arm_security_contact_notifications_enabled

import rego.v1

import data.vulnetix.fugue.arm

metadata := {
	"id": "FUGUE-ARM-SEC-01",
	"name": "Security Center 'Send email notification for high severity alerts' should be enabled",
	"description": "Security Center email notifications ensure that the appropriate individuals in an organization are notified when issues occur, speeding up time to remediation. If using the Azure CLI or API, notifications are sent for \"high\" or greater severity alerts. If using the Azure Portal, users have the additional option of configuring the severity level.",
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
	"tags": ["arm", "azure", "security-center", "alerting"],
}

_ok(r) if {
	lower(object.get(r.resource.properties, "alertNotifications", "")) == "on"
}

findings contains finding if {
	some r in arm.resources("Microsoft.Security/securityContacts")
	not _ok(r)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Security contact %q does not have alertNotifications=on.", [r.resource.name]),
		"artifact_uri": r.path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": 1,
		"snippet": sprintf("%s/%s", [r.resource.type, r.resource.name]),
	}
}
