# Adapted from https://github.com/fugue/regula (FG_R00270).
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.fugue_tf_aws_rsh_01

import rego.v1

import data.vulnetix.fugue.tf

metadata := {
	"id": "FUGUE-TF-AWS-RSH-01",
	"name": "Redshift clusters should not be publicly accessible",
	"description": "Publicly accessible Redshift clusters allow any AWS user or anonymous user access to the data in the database.",
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
	"tags": ["terraform", "aws", "redshift", "public"],
}

findings contains finding if {
	some r in tf.resources("aws_redshift_cluster")
	_is_public(r.block)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("aws_redshift_cluster %q is publicly accessible.", [r.name]),
		"artifact_uri": r.path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": 1,
		"snippet": sprintf("%s.%s", [r.type, r.name]),
	}
}

_is_public(block) if not tf.has_key(block, "publicly_accessible")

_is_public(block) if tf.bool_attr(block, "publicly_accessible") == true
