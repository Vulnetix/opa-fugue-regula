# Adapted from https://github.com/fugue/regula (FG_R00342).
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.fugue_tf_az_mon_log_profile_locations

import rego.v1

import data.vulnetix.fugue.tf

metadata := {
	"id": "FUGUE-TF-AZ-MON-03",
	"name": "Monitor log profile should have activity logs for global services and all regions",
	"description": "Monitor log profile should have activity logs for global services and all regions. Configure the log profile to export activities from all Azure supported regions/locations including global.",
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
	not _has_global(r.block)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Log profile %q does not include the 'global' location in its locations list.", [r.name]),
		"artifact_uri": r.path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": 1,
		"snippet": sprintf("%s.%s", [r.type, r.name]),
	}
}

_has_global(block) if {
	locs := tf.string_list_attr(block, "locations")
	lowers := {lower(l) | some l in locs}
	"global" in lowers
}
