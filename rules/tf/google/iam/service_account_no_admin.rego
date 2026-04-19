# Adapted from https://github.com/fugue/regula (FG_R00384).
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.fugue_tf_gcp_iam_service_account_no_admin

import rego.v1

import data.vulnetix.fugue.tf

metadata := {
	"id": "FUGUE-TF-GCP-IAM-03",
	"name": "User-managed service accounts should not have admin privileges",
	"description": "User-managed service accounts should not have admin privileges. A service account is a special Google account that belongs to an application or a VM instead of to an individual end-user. Service accounts should not have admin privileges as they give full access to an assigned application or a VM, and a service account can perform critical actions like delete, update, etc. without user intervention.",
	"help_uri": "https://github.com/fugue/regula",
	"languages": ["terraform", "hcl"],
	"severity": "high",
	"level": "error",
	"kind": "iac",
	"cwe": ["CWE-269"],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["terraform", "gcp", "iam", "service-account"],
}

# Members (projects IAM) that hold any admin-like role.
_admin_members contains m if {
	some r in tf.resources("google_project_iam_binding")
	_is_admin_role(tf.string_attr(r.block, "role"))
	some m in tf.string_list_attr(r.block, "members")
}

_admin_members contains m if {
	some r in tf.resources("google_project_iam_member")
	_is_admin_role(tf.string_attr(r.block, "role"))
	m := tf.string_attr(r.block, "member")
}

_is_admin_role(role) if endswith(lower(role), "admin")
_is_admin_role(role) if role == "roles/editor"
_is_admin_role(role) if role == "roles/owner"

findings contains finding if {
	some sa in tf.resources("google_service_account")
	account_id := tf.string_attr(sa.block, "account_id")
	account_id != ""
	some m in _admin_members
	_member_matches_account(m, account_id, sa.name)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("google_service_account %q appears to hold an admin/editor/owner role via %q.", [sa.name, m]),
		"artifact_uri": sa.path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": 1,
		"snippet": sprintf("%s.%s", [sa.type, sa.name]),
	}
}

# The IAM binding members are of form "serviceAccount:<account_id>@<project>.iam.gserviceaccount.com"
# or can reference "serviceAccount:${google_service_account.<name>.email}".
_member_matches_account(member, account_id, _) if {
	regex.match(sprintf(`^serviceAccount:%s@`, [regex.replace(account_id, `[.]`, `\.`)]), member)
}

_member_matches_account(member, _, sa_name) if {
	regex.match(sprintf(`google_service_account\.%s\.(email|id|name)`, [sa_name]), member)
}
