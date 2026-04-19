# Adapted from https://github.com/fugue/regula (FG_R00383).
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.fugue_tf_gcp_iam_service_account_no_user_keys

import rego.v1

import data.vulnetix.fugue.tf

metadata := {
	"id": "FUGUE-TF-GCP-IAM-04",
	"name": "Service accounts should only have Google-managed service account keys",
	"description": "Service accounts should only have Google-managed service account keys. Google-managed service account keys are automatically managed and rotated by Google and cannot be downloaded. For user-managed service account keys, the user must take ownership of management activities including key storage, distribution, revocation, and rotation. And even with key owner precautions, user-managed keys can be easily leaked into source code or left on support blogs. Google-managed service account keys should therefore be used.",
	"help_uri": "https://github.com/fugue/regula",
	"languages": ["terraform", "hcl"],
	"severity": "medium",
	"level": "warning",
	"kind": "iac",
	"cwe": ["CWE-522"],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["terraform", "gcp", "iam", "service-account", "credentials"],
}

findings contains finding if {
	some sa in tf.resources("google_service_account")
	_has_user_key(sa)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("google_service_account %q has a user-managed google_service_account_key.", [sa.name]),
		"artifact_uri": sa.path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": 1,
		"snippet": sprintf("%s.%s", [sa.type, sa.name]),
	}
}

_has_user_key(sa) if {
	some key in tf.resources("google_service_account_key")
	tf.references(key.block, "google_service_account", sa.name)
}
