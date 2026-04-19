# Adapted from https://github.com/fugue/regula (FG_R00420).
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.fugue_tf_gcp_gcs_not_public

import rego.v1

import data.vulnetix.fugue.tf

metadata := {
	"id": "FUGUE-TF-GCP-GCS-01",
	"name": "Storage buckets should not be anonymously or publicly accessible",
	"description": "Storage buckets should not be anonymously or publicly accessible. Cloud Storage bucket permissions should not be configured to allow 'allUsers' or 'allAuthenticatedUsers' access. These permissions provides broad, public access, which can result in unknown or undesired data access.",
	"help_uri": "https://github.com/fugue/regula",
	"languages": ["terraform", "hcl"],
	"severity": "critical",
	"level": "error",
	"kind": "iac",
	"cwe": ["CWE-284"],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["terraform", "gcp", "storage", "public-access"],
}

_anonymous := {"allUsers", "allAuthenticatedUsers"}

findings contains finding if {
	some bucket in tf.resources("google_storage_bucket")
	_bucket_public(bucket.name)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("google_storage_bucket %q grants access to allUsers or allAuthenticatedUsers via a bucket IAM resource.", [bucket.name]),
		"artifact_uri": bucket.path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": 1,
		"snippet": sprintf("%s.%s", [bucket.type, bucket.name]),
	}
}

_bucket_public(bucket_name) if {
	some r in tf.resources("google_storage_bucket_iam_binding")
	tf.references(r.block, "google_storage_bucket", bucket_name)
	some m in tf.string_list_attr(r.block, "members")
	m in _anonymous
}

_bucket_public(bucket_name) if {
	some r in tf.resources("google_storage_bucket_iam_member")
	tf.references(r.block, "google_storage_bucket", bucket_name)
	tf.string_attr(r.block, "member") in _anonymous
}

_bucket_public(bucket_name) if {
	some r in tf.resources("google_storage_bucket_access_control")
	tf.references(r.block, "google_storage_bucket", bucket_name)
	tf.string_attr(r.block, "entity") in {"allUsers", "allAuthenticatedUsers"}
}
