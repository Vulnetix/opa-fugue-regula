# Adapted from https://github.com/fugue/regula (FG_R00386).
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.fugue_tf_gcp_kms_no_anonymous_access

import rego.v1

import data.vulnetix.fugue.tf

metadata := {
	"id": "FUGUE-TF-GCP-KMS-02",
	"name": "KMS keys should not be anonymously or publicly accessible",
	"description": "KMS keys should not be anonymously or publicly accessible. IAM policy on Cloud KMS cryptokeys should restrict anonymous and/or public access. Granting permissions to `allUsers` or `allAuthenticatedUsers` allows anyone to access the dataset, which is not desirable if sensitive data is stored at the location.",
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
	"tags": ["terraform", "gcp", "kms", "public-access"],
}

_anonymous := {"allUsers", "allAuthenticatedUsers"}

# Anonymous access granted at the project level on any cloudkms role.
_project_anonymous_cloudkms if {
	some r in tf.resources("google_project_iam_binding")
	startswith(tf.string_attr(r.block, "role"), "roles/cloudkms")
	some m in tf.string_list_attr(r.block, "members")
	m in _anonymous
}

_project_anonymous_cloudkms if {
	some r in tf.resources("google_project_iam_member")
	startswith(tf.string_attr(r.block, "role"), "roles/cloudkms")
	tf.string_attr(r.block, "member") in _anonymous
}

findings contains finding if {
	some key in tf.resources("google_kms_crypto_key")
	_project_anonymous_cloudkms
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("google_kms_crypto_key %q is affected by a project-level cloudkms binding to allUsers/allAuthenticatedUsers.", [key.name]),
		"artifact_uri": key.path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": 1,
		"snippet": sprintf("%s.%s", [key.type, key.name]),
	}
}

findings contains finding if {
	some key in tf.resources("google_kms_crypto_key")
	_key_scoped_anonymous(key.name)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("google_kms_crypto_key %q grants allUsers or allAuthenticatedUsers via a key-scoped IAM resource.", [key.name]),
		"artifact_uri": key.path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": 1,
		"snippet": sprintf("%s.%s", [key.type, key.name]),
	}
}

_key_scoped_anonymous(key_name) if {
	some r in tf.resources("google_kms_crypto_key_iam_binding")
	tf.references(r.block, "google_kms_crypto_key", key_name)
	some m in tf.string_list_attr(r.block, "members")
	m in _anonymous
}

_key_scoped_anonymous(key_name) if {
	some r in tf.resources("google_kms_crypto_key_iam_member")
	tf.references(r.block, "google_kms_crypto_key", key_name)
	tf.string_attr(r.block, "member") in _anonymous
}
