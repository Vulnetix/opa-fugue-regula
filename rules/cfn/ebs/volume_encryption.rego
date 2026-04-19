# Adapted from https://github.com/fugue/regula (FG_R00016).
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.fugue_cfn_ebs_volume_encryption

import rego.v1

import data.vulnetix.fugue.cfn

metadata := {
	"id": "FUGUE-CFN-EBS-01",
	"name": "EBS volume encryption should be enabled",
	"description": "EBS volume encryption should be enabled. Enabling encryption on EBS volumes protects data at rest inside the volume, data in transit between the volume and instance, snapshots, and volumes created from those snapshots.",
	"help_uri": "https://github.com/fugue/regula",
	"languages": ["yaml", "json"],
	"severity": "high",
	"level": "error",
	"kind": "iac",
	"cwe": ["CWE-311"],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["cloudformation", "aws", "ebs", "encryption"],
}

findings contains finding if {
	some r in cfn.resources("AWS::EC2::Volume")
	props := cfn.properties(r)
	not props.Encrypted == true
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("EBS Volume %q does not have Encrypted set to true.", [r.logical_id]),
		"artifact_uri": r.path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": 1,
		"snippet": sprintf("AWS::EC2::Volume/%s", [r.logical_id]),
	}
}
