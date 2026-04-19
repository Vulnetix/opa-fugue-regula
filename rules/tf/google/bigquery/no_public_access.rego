# Adapted from https://github.com/fugue/regula (FG_R00437).
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.fugue_tf_gcp_bigquery_no_public_access

import rego.v1

import data.vulnetix.fugue.tf

metadata := {
	"id": "FUGUE-TF-GCP-BQ-01",
	"name": "BigQuery datasets should not be anonymously or publicly accessible",
	"description": "BigQuery datasets should not be anonymously or publicly accessible. BigQuery datasets should not grant the 'allUsers' or 'allAuthenticatedUsers' permissions because these will allow anyone to access the dataset and any stored sensitive data.",
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
	"tags": ["terraform", "gcp", "bigquery", "public-access"],
}

findings contains finding if {
	some r in tf.resources("google_bigquery_dataset")
	_has_anonymous_access(r.block)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("BigQuery dataset %q grants access to allUsers or allAuthenticatedUsers.", [r.name]),
		"artifact_uri": r.path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": 1,
		"snippet": sprintf("%s.%s", [r.type, r.name]),
	}
}

_has_anonymous_access(block) if {
	some access in tf.sub_blocks(block, "access")
	regex.match(`(special_group|iam_member)\s*=\s*"(allUsers|allAuthenticatedUsers)"`, access)
}
