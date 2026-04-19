# Adapted from https://github.com/fugue/regula (FG_R00393).
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.fugue_tf_gcp_log_bucket_lock

import rego.v1

import data.vulnetix.fugue.tf

metadata := {
	"id": "FUGUE-TF-GCP-LOG-03",
	"name": "Logging storage bucket retention policies and Bucket Lock should be configured",
	"description": "Logging storage bucket retention policies and Bucket Lock should be configured. A retention policy for a Cloud Storage bucket governs how long objects in the bucket must be retained. Bucket Lock is a feature to permanently restrict edits to the data retention policy. Bucket Lock should be enabled because it preserves activity logs for forensics and security investigations if the system is compromised by an attacker or malicious insider who wants to cover their tracks.",
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
	"tags": ["terraform", "gcp", "logging", "storage"],
}

findings contains finding if {
	some bucket in tf.resources("google_storage_bucket")
	_is_sink_destination(bucket)
	not _has_locked_retention(bucket.block)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("google_storage_bucket %q is a logging sink destination without a locked retention_policy.", [bucket.name]),
		"artifact_uri": bucket.path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": 1,
		"snippet": sprintf("%s.%s", [bucket.type, bucket.name]),
	}
}

_is_sink_destination(bucket) if {
	some sink in tf.resources("google_logging_project_sink")
	tf.references(sink.block, "google_storage_bucket", bucket.name)
}

_has_locked_retention(block) if {
	some rp in tf.sub_blocks(block, "retention_policy")
	tf.bool_attr(rp, "is_locked") == true
}
