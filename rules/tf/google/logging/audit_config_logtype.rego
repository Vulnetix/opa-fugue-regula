# Adapted from https://github.com/fugue/regula (FG_R00389).
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.fugue_tf_gcp_log_audit_config_logtype

import rego.v1

import data.vulnetix.fugue.tf

metadata := {
	"id": "FUGUE-TF-GCP-LOG-02",
	"name": "IAM default audit log config should include 'DATA_READ' and 'DATA_WRITE' log types",
	"description": "IAM default audit log config should include 'DATA_READ' and 'DATA_WRITE' log types. A best practice is to enable 'DATA_READ' and 'DATA_WRITE' data access log types as part of the default IAM audit log config, so that read and write operations on user-provided data are tracked across all relevant services. Please note that the 'ADMIN_WRITE' log type and BigQuery data access logs are enabled by default.",
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
	not _has_required_logtypes(r.block)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("google_project_iam_audit_config %q (default) is missing DATA_READ and/or DATA_WRITE log types.", [r.name]),
		"artifact_uri": r.path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": 1,
		"snippet": sprintf("%s.%s", [r.type, r.name]),
	}
}

_has_required_logtypes(block) if {
	types := {t |
		some cfg in tf.sub_blocks(block, "audit_log_config")
		t := tf.string_attr(cfg, "log_type")
	}
	"DATA_READ" in types
	"DATA_WRITE" in types
}
