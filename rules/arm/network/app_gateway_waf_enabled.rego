# Adapted from https://github.com/fugue/regula (FG_R00224).
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.fugue_arm_network_app_gateway_waf_enabled

import rego.v1

import data.vulnetix.fugue.arm

metadata := {
	"id": "FUGUE-ARM-NET-01",
	"name": "Ensure Azure Application Gateway Web application firewall (WAF) is enabled",
	"description": "Azure Application Gateway offers a web application firewall (WAF) that provides centralized protection of your web applications from common exploits and vulnerabilities. Web applications are increasingly targeted by malicious attacks that exploit commonly known vulnerabilities.",
	"help_uri": "https://github.com/fugue/regula",
	"languages": ["json"],
	"severity": "medium",
	"level": "warning",
	"kind": "iac",
	"cwe": ["CWE-693"],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["arm", "azure", "network", "waf"],
}

_waf_tiers := {"WAF", "WAF_v2"}

_ok(r) if {
	tier := r.resource.properties.sku.tier
	tier in _waf_tiers
	r.resource.properties.webApplicationFirewallConfiguration.enabled == true
}

findings contains finding if {
	some r in arm.resources("Microsoft.Network/applicationGateways")
	not _ok(r)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Application Gateway %q does not have WAF enabled.", [r.resource.name]),
		"artifact_uri": r.path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": 1,
		"snippet": sprintf("%s/%s", [r.resource.type, r.resource.name]),
	}
}
