# Adapted from https://github.com/fugue/regula (FG_R00152).
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.fugue_tf_az_sa_secure_transfer

import rego.v1

import data.vulnetix.fugue.tf

metadata := {
	"id": "FUGUE-TF-AZ-SA-04",
	"name": "Storage Accounts 'Secure transfer required' should be enabled",
	"description": "Storage Accounts 'Secure transfer required' should be enabled. The secure transfer option enhances the security of a storage account by only allowing requests to the storage account by a secure connection.",
	"help_uri": "https://github.com/fugue/regula",
	"languages": ["terraform", "hcl"],
	"severity": "medium",
	"level": "warning",
	"kind": "iac",
	"cwe": ["CWE-319"],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["terraform", "azure", "storage", "https"],
}

findings contains finding if {
	some r in tf.resources("azurerm_storage_account")
	not tf.bool_attr(r.block, "enable_https_traffic_only") == true
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Storage account %q does not set enable_https_traffic_only = true.", [r.name]),
		"artifact_uri": r.path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": 1,
		"snippet": sprintf("%s.%s", [r.type, r.name]),
	}
}
