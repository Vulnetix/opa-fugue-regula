# Adapted from https://github.com/fugue/regula (FG_R00342).
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.fugue_arm_monitor_log_profile_global_locations

import rego.v1

import data.vulnetix.fugue.arm

metadata := {
	"id": "FUGUE-ARM-MON-03",
	"name": "Monitor log profile should have activity logs for global services and all regions",
	"description": "Configure the log profile to export activities from all Azure supported regions/locations including global. This rule is evaluated against all resource locations that can be observed in the template.",
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

# Simplification: upstream pulls locations from ALL scanned resources in the
# cloud account. In our static-file context we derive used_locations from
# locations observed on sibling resources in the same template.
_used_locations(template_path) := locs if {
	locs := {lower(l) |
		some r in arm.all_resources
		r.path == template_path
		l := object.get(r.resource, "location", "")
		l != ""
	}
}

_required_locations(template_path) := _used_locations(template_path) | {"global"}

_profile_ok(profile_entry) if {
	req := _required_locations(profile_entry.path)
	locs := {lower(l) | some l in object.get(profile_entry.resource.properties, "locations", [])}
	count(req - locs) == 0
}

findings contains finding if {
	some p in arm.resources("Microsoft.Insights/logprofiles")
	not _profile_ok(p)
	missing := concat(", ", _required_locations(p.path) - {lower(l) | some l in object.get(p.resource.properties, "locations", [])})
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Log profile %q is missing locations: %s", [p.resource.name, missing]),
		"artifact_uri": p.path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": 1,
		"snippet": sprintf("%s/%s", [p.resource.type, p.resource.name]),
	}
}
