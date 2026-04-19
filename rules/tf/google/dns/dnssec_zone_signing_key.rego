# Adapted from https://github.com/fugue/regula (FG_R00406).
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.fugue_tf_gcp_dns_dnssec_zone_signing_key

import rego.v1

import data.vulnetix.fugue.tf

metadata := {
	"id": "FUGUE-TF-GCP-DNS-03",
	"name": "DNS managed zone DNSSEC zone-signing keys should not use RSASHA1",
	"description": "DNS managed zone DNSSEC zone-signing keys should not use RSASHA1. Domain Name System Security Extensions (DNSSEC) algorithm numbers may be used in CERT RRs. Zone signing (DNSSEC) and transaction security mechanisms (SIG(0) and TSIG) make use of particular subsets of these algorithms. The zone-signing key algorithm should be strong, and RSASHA1 is no longer considered secure. Use it only for compatibility reasons.",
	"help_uri": "https://github.com/fugue/regula",
	"languages": ["terraform", "hcl"],
	"severity": "high",
	"level": "error",
	"kind": "iac",
	"cwe": ["CWE-327"],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["terraform", "gcp", "dns", "dnssec"],
}

findings contains finding if {
	some r in tf.resources("google_dns_managed_zone")
	_dnssec_on(r.block)
	_has_weak_zone_signing(r.block)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("google_dns_managed_zone %q uses RSASHA1 for a zone-signing default_key_specs entry.", [r.name]),
		"artifact_uri": r.path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": 1,
		"snippet": sprintf("%s.%s", [r.type, r.name]),
	}
}

findings contains finding if {
	some r in tf.resources("google_dns_managed_zone")
	not _dnssec_on(r.block)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("google_dns_managed_zone %q does not have DNSSEC enabled.", [r.name]),
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

_has_weak_zone_signing(block) if {
	some cfg in tf.sub_blocks(block, "dnssec_config")
	some spec in tf.sub_blocks(cfg, "default_key_specs")
	tf.string_attr(spec, "key_type") == "zoneSigning"
	tf.string_attr(spec, "algorithm") == "rsasha1"
}
