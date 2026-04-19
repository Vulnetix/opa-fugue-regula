# Adapted from https://github.com/fugue/regula (FG_R00409).
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.fugue_tf_gcp_gce_subnetwork_flow_logs

import rego.v1

import data.vulnetix.fugue.tf

metadata := {
	"id": "FUGUE-TF-GCP-GCE-13",
	"name": "Network subnet flow logs should be enabled",
	"description": "Network subnet flow logs should be enabled. It is recommended that flow logs be enabled for every business-critical VPC subnet, as they provide visibility into network traffic for each VM inside the subnet and can be used to detect anomalous traffic or insight during security workflows.",
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
	"tags": ["terraform", "gcp", "compute", "logging"],
}

findings contains finding if {
	some r in tf.resources("google_compute_subnetwork")
	not tf.has_sub_block(r.block, "log_config")
	not tf.bool_attr(r.block, "enable_flow_logs") == true
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("google_compute_subnetwork %q does not enable flow logs (log_config).", [r.name]),
		"artifact_uri": r.path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": 1,
		"snippet": sprintf("%s.%s", [r.type, r.name]),
	}
}
