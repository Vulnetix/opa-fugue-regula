# Adapted from https://github.com/fugue/regula (FG_R00388).
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.fugue_tf_gcp_iam_kms_role_limits

import rego.v1

import data.vulnetix.fugue.tf

metadata := {
	"id": "FUGUE-TF-GCP-IAM-01",
	"name": "IAM users should not have both KMS admin and any of the KMS encrypter/decrypter roles",
	"description": "IAM users should not have both KMS admin and any of the KMS encrypter/decrypter roles. No user should have both KMS admin and encrypter/decrypter roles because they could create a key then immediately use it to encrypt/decrypt data. Separation of duties ensures that no one individual has all necessary permissions to complete a malicious action.",
	"help_uri": "https://github.com/fugue/regula",
	"languages": ["terraform", "hcl"],
	"severity": "medium",
	"level": "warning",
	"kind": "iac",
	"cwe": ["CWE-269"],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["terraform", "gcp", "iam", "kms"],
}

_kms_admin_role := "roles/cloudkms.admin"

_kms_crypto_roles := {
	"roles/cloudkms.cryptoKeyEncrypterDecrypter",
	"roles/cloudkms.cryptoKeyEncrypter",
	"roles/cloudkms.cryptoKeyDecrypter",
}

# Collect members that have the KMS admin role at project level.
_admin_members contains m if {
	some r in _project_iam_bindings_with_role(_kms_admin_role)
	some m in tf.string_list_attr(r.block, "members")
}

_admin_members contains m if {
	some r in tf.resources("google_project_iam_member")
	tf.string_attr(r.block, "role") == _kms_admin_role
	m := tf.string_attr(r.block, "member")
}

# Members that have any of the KMS crypto roles at project level.
_crypto_members contains m if {
	some role in _kms_crypto_roles
	some r in _project_iam_bindings_with_role(role)
	some m in tf.string_list_attr(r.block, "members")
}

_crypto_members contains m if {
	some role in _kms_crypto_roles
	some r in tf.resources("google_project_iam_member")
	tf.string_attr(r.block, "role") == role
	m := tf.string_attr(r.block, "member")
}

_project_iam_bindings_with_role(role) := out if {
	out := [r |
		some r in tf.resources("google_project_iam_binding")
		tf.string_attr(r.block, "role") == role
	]
}

findings contains finding if {
	some r in tf.resources("google_project_iam_binding")
	role := tf.string_attr(r.block, "role")
	role == _kms_admin_role
	some m in tf.string_list_attr(r.block, "members")
	m in _crypto_members
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Member %q is granted KMS admin plus a KMS crypto role in %s %q.", [m, r.type, r.name]),
		"artifact_uri": r.path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": 1,
		"snippet": sprintf("%s.%s", [r.type, r.name]),
	}
}

findings contains finding if {
	some r in tf.resources("google_project_iam_member")
	tf.string_attr(r.block, "role") == _kms_admin_role
	m := tf.string_attr(r.block, "member")
	m in _crypto_members
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Member %q is granted KMS admin plus a KMS crypto role in %s %q.", [m, r.type, r.name]),
		"artifact_uri": r.path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": 1,
		"snippet": sprintf("%s.%s", [r.type, r.name]),
	}
}
