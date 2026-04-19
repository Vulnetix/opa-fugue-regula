# Adapted from https://github.com/fugue/regula (FG_R00419).
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.fugue_tf_gcp_gce_no_public_ip

import rego.v1

import data.vulnetix.fugue.tf

metadata := {
	"id": "FUGUE-TF-GCP-GCE-09",
	"name": "Compute instances should not have public IP addresses",
	"description": "Compute instances should not have public IP addresses. Compute Engine instances should not have public IP addresses to reduce potential attack surfaces, as public IPs enable direct access via the internet. Instances serving internet traffic should be configured behind load balancers, which provide an additional layer of security.",
	"help_uri": "https://github.com/fugue/regula",
	"languages": ["terraform", "hcl"],
	"severity": "medium",
	"level": "warning",
	"kind": "iac",
	"cwe": ["CWE-284"],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["terraform", "gcp", "compute", "networking"],
}

findings contains finding if {
	some r in tf.resources("google_compute_instance")
	some ni in tf.sub_blocks(r.block, "network_interface")
	tf.has_sub_block(ni, "access_config")
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("google_compute_instance %q has a network_interface with access_config (public IP).", [r.name]),
		"artifact_uri": r.path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": 1,
		"snippet": sprintf("%s.%s", [r.type, r.name]),
	}
}
