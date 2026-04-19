# Adapted from https://github.com/fugue/regula (FG_R00411).
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.fugue_tf_gcp_gce_no_default_service_account

import rego.v1

import data.vulnetix.fugue.tf

metadata := {
	"id": "FUGUE-TF-GCP-GCE-07",
	"name": "Compute instances should not use the default service account",
	"description": "Compute instances should not use the default service account. The default Compute Engine service account has an \"Editor\" role, which allows read and write access to most Google Cloud services. To apply the principle of least privileges and mitigate the risk of a Compute Engine instance being compromised, create a new service account for an instance with only the necessary permissions assigned. Note that GKE-created instances should be exempted from this.",
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
	"tags": ["terraform", "gcp", "compute", "iam"],
}

findings contains finding if {
	some r in tf.resources("google_compute_instance")
	some sa in tf.sub_blocks(r.block, "service_account")
	_is_default_service_account(sa)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("google_compute_instance %q uses the default Compute Engine service account.", [r.name]),
		"artifact_uri": r.path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": 1,
		"snippet": sprintf("%s.%s", [r.type, r.name]),
	}
}

# Default service account email is: <project>-compute@developer.gserviceaccount.com
# Omitting email also means default SA.
_is_default_service_account(sa) if {
	email := tf.string_attr(sa, "email")
	regex.match(`compute@developer\.gserviceaccount\.com`, email)
}

_is_default_service_account(sa) if {
	not tf.has_key(sa, "email")
}
