# Adapted from https://github.com/fugue/regula (FG_R00224).
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.fugue_tf_az_net_appgw_waf

import rego.v1

import data.vulnetix.fugue.tf

metadata := {
	"id": "FUGUE-TF-AZ-NET-01",
	"name": "Ensure Azure Application Gateway Web application firewall (WAF) is enabled",
	"description": "Ensure Azure Application Gateway Web application firewall (WAF) is enabled. Azure Application Gateway offers a WAF that provides centralized protection of web applications from common exploits and vulnerabilities.",
	"help_uri": "https://github.com/fugue/regula",
	"languages": ["terraform", "hcl"],
	"severity": "medium",
	"level": "warning",
	"kind": "iac",
	"cwe": ["CWE-693"],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["terraform", "azure", "network", "waf"],
}

findings contains finding if {
	some r in tf.resources("azurerm_application_gateway")
	not _valid_waf(r.block)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Application Gateway %q does not have WAF SKU tier with waf_configuration.enabled = true.", [r.name]),
		"artifact_uri": r.path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": 1,
		"snippet": sprintf("%s.%s", [r.type, r.name]),
	}
}

_valid_waf(block) if {
	_has_waf_sku(block)
	_waf_enabled(block)
}

_has_waf_sku(block) if {
	some sku in tf.sub_blocks(block, "sku")
	tier := tf.string_attr(sku, "tier")
	tier in {"WAF", "WAF_v2"}
}

_waf_enabled(block) if {
	some wc in tf.sub_blocks(block, "waf_configuration")
	tf.bool_attr(wc, "enabled") == true
}
