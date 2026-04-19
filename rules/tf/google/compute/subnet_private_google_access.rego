# Adapted from https://github.com/fugue/regula (FG_R00438).
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.fugue_tf_gcp_gce_subnet_private_google_access

import rego.v1

import data.vulnetix.fugue.tf

metadata := {
	"id": "FUGUE-TF-GCP-GCE-12",
	"name": "VPC subnet 'Private Google Access' should be enabled",
	"description": "Enabling \"Private Google Access\" for VPC subnets allows virtual machines to connect to the external IP addresses used by Google APIs and services.",
	"help_uri": "https://github.com/fugue/regula",
	"languages": ["terraform", "hcl"],
	"severity": "low",
	"level": "note",
	"kind": "iac",
	"cwe": ["CWE-284"],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["terraform", "gcp", "compute", "networking"],
}

findings contains finding if {
	some r in tf.resources("google_compute_subnetwork")
	tf.is_not_true(r.block, "private_ip_google_access")
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("google_compute_subnetwork %q does not enable private_ip_google_access.", [r.name]),
		"artifact_uri": r.path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": 1,
		"snippet": sprintf("%s.%s", [r.type, r.name]),
	}
}
