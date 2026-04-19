# Adapted from https://github.com/fugue/regula (FG_R00404).
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.fugue_tf_gcp_dns_dnssec_enabled

import rego.v1

import data.vulnetix.fugue.tf

metadata := {
	"id": "FUGUE-TF-GCP-DNS-01",
	"name": "DNS managed zone DNSSEC should be enabled",
	"description": "DNS managed zone DNSSEC should be enabled. Attackers can hijack the process of domain/IP lookup and redirect users to a malicious site. Domain Name System Security Extensions (DNSSEC) cryptographically signs DNS records and can help prevent attackers from issuing fake DNS responses that redirect browsers.",
	"help_uri": "https://github.com/fugue/regula",
	"languages": ["terraform", "hcl"],
	"severity": "medium",
	"level": "warning",
	"kind": "iac",
	"cwe": ["CWE-345"],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["terraform", "gcp", "dns", "dnssec"],
}

findings contains finding if {
	some r in tf.resources("google_dns_managed_zone")
	not _dnssec_on(r.block)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("google_dns_managed_zone %q does not have dnssec_config.state = \"on\".", [r.name]),
		"artifact_uri": r.path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": 1,
		"snippet": sprintf("%s.%s", [r.type, r.name]),
	}
}

_dnssec_on(block) if {
	some cfg in tf.sub_blocks(block, "dnssec_config")
	tf.string_attr(cfg, "state") == "on"
}
