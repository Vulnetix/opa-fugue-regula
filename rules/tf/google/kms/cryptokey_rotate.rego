# Adapted from https://github.com/fugue/regula (FG_R00378).
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.fugue_tf_gcp_kms_cryptokey_rotate

import rego.v1

import data.vulnetix.fugue.tf

metadata := {
	"id": "FUGUE-TF-GCP-KMS-01",
	"name": "KMS keys should be rotated every 90 days or less",
	"description": "KMS keys should be rotated frequently because rotation helps reduce the potential impact of a compromised key as users cannot use the old key to access the data.",
	"help_uri": "https://github.com/fugue/regula",
	"languages": ["terraform", "hcl"],
	"severity": "medium",
	"level": "warning",
	"kind": "iac",
	"cwe": ["CWE-320"],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["terraform", "gcp", "kms", "rotation"],
}

findings contains finding if {
	some r in tf.resources("google_kms_crypto_key")
	not _rotation_ok(r.block)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("google_kms_crypto_key %q has no rotation_period or a rotation_period > 90 days.", [r.name]),
		"artifact_uri": r.path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": 1,
		"snippet": sprintf("%s.%s", [r.type, r.name]),
	}
}

# 90 days in seconds = 7776000.
_rotation_ok(block) if {
	rp := tf.string_attr(block, "rotation_period")
	trimmed := trim_right(rp, "s")
	num := to_number(trimmed)
	num <= 7776000
}
