# Adapted from https://github.com/fugue/regula (FG_R00421).
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.fugue_tf_gcp_gcs_uniform_access

import rego.v1

import data.vulnetix.fugue.tf

metadata := {
	"id": "FUGUE-TF-GCP-GCS-02",
	"name": "Storage bucket uniform access control should be enabled",
	"description": "Storage bucket uniform access control should be enabled. Permissions for Cloud Storage can be granted using Cloud IAM or ACLs. Cloud IAM allows permissions at the bucket and project levels, whereas ACLs are only used by Cloud Storage, but allow per-object permissions. Uniform bucket-level access disables ACLs, which ensures that only Cloud IAM is used for permissions. This ensures that bucket-level and/or project-level permissions will be the same as object-level permissions.",
	"help_uri": "https://github.com/fugue/regula",
	"languages": ["terraform", "hcl"],
	"severity": "medium",
	"level": "warning",
	"kind": "iac",
	"cwe": ["CWE-284"],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["terraform", "gcp", "storage"],
}

findings contains finding if {
	some r in tf.resources("google_storage_bucket")
	tf.is_not_true(r.block, "uniform_bucket_level_access")
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("google_storage_bucket %q does not enable uniform_bucket_level_access.", [r.name]),
		"artifact_uri": r.path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": 1,
		"snippet": sprintf("%s.%s", [r.type, r.name]),
	}
}
