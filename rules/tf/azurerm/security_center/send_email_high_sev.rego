# Adapted from https://github.com/fugue/regula (FG_R00468).
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.fugue_tf_az_sc_email_high_sev

import rego.v1

import data.vulnetix.fugue.tf

metadata := {
	"id": "FUGUE-TF-AZ-SC-01",
	"name": "Security Center 'Send email notification for high severity alerts' should be enabled",
	"description": "Security Center 'Send email notification for high severity alerts' should be enabled. Security Center email notifications ensure that the appropriate individuals in an organization are notified when issues occur, speeding up time to remediation.",
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
	"tags": ["terraform", "azure", "security-center", "notifications"],
}

findings contains finding if {
	some r in tf.resources("azurerm_security_center_contact")
	not tf.bool_attr(r.block, "alert_notifications") == true
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Security Center contact %q does not set alert_notifications = true.", [r.name]),
		"artifact_uri": r.path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": 1,
		"snippet": sprintf("%s.%s", [r.type, r.name]),
	}
}
