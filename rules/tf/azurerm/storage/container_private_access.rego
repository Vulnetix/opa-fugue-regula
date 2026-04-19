# Adapted from https://github.com/fugue/regula (FG_R00207).
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.fugue_tf_az_sa_container_private

import rego.v1

import data.vulnetix.fugue.tf

metadata := {
	"id": "FUGUE-TF-AZ-SA-01",
	"name": "Blob Storage containers should have public access disabled",
	"description": "Blob Storage containers should have public access disabled. Anonymous, public read access to a container and its blobs can be enabled in Azure Blob storage. A shared access signature token should be used for providing controlled and timed access.",
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
	"tags": ["terraform", "azure", "storage", "public-access"],
}

findings contains finding if {
	some r in tf.resources("azurerm_storage_container")
	not tf.string_attr(r.block, "container_access_type") == "private"
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Storage container %q does not have container_access_type = \"private\".", [r.name]),
		"artifact_uri": r.path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": 1,
		"snippet": sprintf("%s.%s", [r.type, r.name]),
	}
}
