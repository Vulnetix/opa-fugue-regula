# Adapted from https://github.com/fugue/regula (FG_R00347).
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.fugue_arm_app_service_min_tls_version

import rego.v1

import data.vulnetix.fugue.arm

metadata := {
	"id": "FUGUE-ARM-AS-04",
	"name": "App Service web apps should have 'Minimum TLS Version' set to '1.2'",
	"description": "The TLS (Transport Layer Security) protocol secures transmission of data over the internet using standard encryption technology. Encryption should be set with the latest version of TLS. App service allows TLS 1.2 by default, which is the recommended TLS level by industry standards.",
	"help_uri": "https://github.com/fugue/regula",
	"languages": ["json"],
	"severity": "medium",
	"level": "warning",
	"kind": "iac",
	"cwe": ["CWE-327"],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["arm", "azure", "app-service", "tls"],
}

_parse_version(str) := ret if {
	parts := regex.find_n(`[0-9]+`, str, -1)
	ret := [n | some p in parts; n := to_number(p)]
}

_min_tls := _parse_version("1.2")

_tls_ok_via_siteconfig(site) if {
	v := site.properties.siteConfig.minTlsVersion
	_parse_version(v) >= _min_tls
}

_config_matches_site(cfg, site) if {
	cfg.resource.type == "Microsoft.Web/sites/config"
	cfg.path == site.path
	startswith(cfg.resource.name, sprintf("%s/", [site.resource.name]))
	endswith(cfg.resource.name, "/web")
}

_tls_ok_via_config(site_path, site) if {
	some cfg in arm.resources("Microsoft.Web/sites/config")
	_config_matches_site(cfg, {"resource": site, "path": site_path})
	v := cfg.resource.properties.minTlsVersion
	_parse_version(v) >= _min_tls
}

_tls_ok(s) if {
	_tls_ok_via_siteconfig(s.resource)
}

_tls_ok(s) if {
	_tls_ok_via_config(s.path, s.resource)
}

findings contains finding if {
	some s in arm.resources("Microsoft.Web/sites")
	not _tls_ok(s)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("App Service site %q does not enforce minimum TLS version 1.2.", [s.resource.name]),
		"artifact_uri": s.path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": 1,
		"snippet": sprintf("%s/%s", [s.resource.type, s.resource.name]),
	}
}
