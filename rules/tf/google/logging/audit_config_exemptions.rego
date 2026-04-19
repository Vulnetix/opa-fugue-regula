# Adapted from https://github.com/fugue/regula (FG_R00391).
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.fugue_tf_gcp_log_audit_config_exemptions

import rego.v1

import data.vulnetix.fugue.tf

metadata := {
	"id": "FUGUE-TF-GCP-LOG-01",
	"name": "IAM default audit log config should not exempt any users",
	"description": "IAM default audit log config should not exempt any users. A project's default audit log config should not exempt any users, to ensure that user admin write operations and data access operations are appropriately logged.",
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
	"tags": ["terraform", "gcp", "logging", "audit"],
}

findings contains finding if {
	some r in tf.resources("google_project_iam_audit_config")
	tf.string_attr(r.block, "service") == "allServices"
	_has_exempted_members(r.block)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("google_project_iam_audit_config %q (default) has exempted_members configured.", [r.name]),
		"artifact_uri": r.path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": 1,
		"snippet": sprintf("%s.%s", [r.type, r.name]),
	}
}

_has_exempted_members(block) if {
	some cfg in tf.sub_blocks(block, "audit_log_config")
	members := tf.string_list_attr(cfg, "exempted_members")
	count(members) > 0
}
