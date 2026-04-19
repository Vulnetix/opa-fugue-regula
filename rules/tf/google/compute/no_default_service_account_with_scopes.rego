# Adapted from https://github.com/fugue/regula (FG_R00412).
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.fugue_tf_gcp_gce_no_default_service_account_with_scopes

import rego.v1

import data.vulnetix.fugue.tf

metadata := {
	"id": "FUGUE-TF-GCP-GCE-08",
	"name": "Compute instances should not use the default service account with full access to all Cloud APIs",
	"description": "Compute instances should not use the default service account with full access to all Cloud APIs. If using the default Compute Engine service account (which is not recommended), note that the \"Editor\" role is assigned with three possible scopes: allow default access, allow full access to all Cloud APIs, and set access for each Cloud API. Avoid allowing the scope for full access to all Cloud APIs, as this may enable users accessing the Compute Engine instance to perform cloud operations outside the scope of responsibility, or increase the potential impact of a compromised instance. Note that GKE-created instances should be exempted from this.",
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
	"tags": ["terraform", "gcp", "compute", "iam"],
}

findings contains finding if {
	some r in tf.resources("google_compute_instance")
	some sa in tf.sub_blocks(r.block, "service_account")
	_is_default_service_account(sa)
	_has_invalid_scope(sa)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("google_compute_instance %q uses the default service account with full cloud-platform scope.", [r.name]),
		"artifact_uri": r.path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": 1,
		"snippet": sprintf("%s.%s", [r.type, r.name]),
	}
}

_is_default_service_account(sa) if {
	email := tf.string_attr(sa, "email")
	regex.match(`compute@developer\.gserviceaccount\.com`, email)
}

_is_default_service_account(sa) if not tf.has_key(sa, "email")

_has_invalid_scope(sa) if {
	some s in tf.string_list_attr(sa, "scopes")
	s == "https://www.googleapis.com/auth/cloud-platform"
}

_has_invalid_scope(sa) if {
	some s in tf.string_list_attr(sa, "scopes")
	s == "cloud-platform"
}
