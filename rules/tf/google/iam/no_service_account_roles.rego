# Adapted from https://github.com/fugue/regula (FG_R00385).
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.fugue_tf_gcp_iam_no_service_account_roles

import rego.v1

import data.vulnetix.fugue.tf

metadata := {
	"id": "FUGUE-TF-GCP-IAM-02",
	"name": "IAM users should not have project-level 'Service Account User' or 'Service Account Token Creator' roles",
	"description": "IAM users should not have project-level 'Service Account User' or 'Service Account Token Creator' roles. Assigning IAM users with project-level 'Service Account User' or 'Service Account Token Creator' roles means that they can potentially access resources across an entire project. To follow least privileges best practice, IAM users should be assigned to a specific service account with more scoped access.",
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

_invalid_roles := {
	"roles/iam.serviceAccountUser",
	"roles/iam.serviceAccountTokenCreator",
}

findings contains finding if {
	some r in tf.resources("google_project_iam_binding")
	role := tf.string_attr(r.block, "role")
	role in _invalid_roles
	members := tf.string_list_attr(r.block, "members")
	count(members) > 0
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("google_project_iam_binding %q grants %q at project level.", [r.name, role]),
		"artifact_uri": r.path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": 1,
		"snippet": sprintf("%s.%s", [r.type, r.name]),
	}
}

findings contains finding if {
	some r in tf.resources("google_project_iam_member")
	role := tf.string_attr(r.block, "role")
	role in _invalid_roles
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("google_project_iam_member %q grants %q at project level.", [r.name, role]),
		"artifact_uri": r.path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": 1,
		"snippet": sprintf("%s.%s", [r.type, r.name]),
	}
}
