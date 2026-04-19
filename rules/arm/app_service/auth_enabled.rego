# Adapted from https://github.com/fugue/regula (FG_R00345).
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.fugue_arm_app_service_auth_enabled

import rego.v1

import data.vulnetix.fugue.arm

metadata := {
	"id": "FUGUE-ARM-AS-01",
	"name": "App Service web app authentication should be enabled",
	"description": "Azure App Service Authentication is a feature that can prevent anonymous HTTP requests from reaching the API app, or authenticate those that have tokens before they reach the API app. If an anonymous request is received from a browser, App Service will redirect to a logon page. To handle the logon process, a choice from a set of identity providers can be made, or a custom authentication mechanism can be implemented.",
	"help_uri": "https://github.com/fugue/regula",
	"languages": ["json"],
	"severity": "medium",
	"level": "warning",
	"kind": "iac",
	"cwe": ["CWE-284"],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["arm", "azure", "app-service", "authentication"],
}

# Site is OK if a sibling/nested Microsoft.Web/sites/config with name
# "authsettings" or "authsettingsv2" is enabled. Match child configs via
# nested config (same parent site) or by checking the site's own authSettings
# property.
_site_name(site) := site.name

_auth_config_enabled(cfg) if {
	cfg.name == "authsettings"
	cfg.properties.enabled == true
}

_auth_config_enabled(cfg) if {
	cfg.name == "authsettingsv2"
	cfg.properties.platform.enabled == true
}

# Match: a config of type Microsoft.Web/sites/config whose name prefix
# references the same site, either as "<site>/authsettings" or nested.
_config_matches_site(cfg, site) if {
	cfg.resource.type == "Microsoft.Web/sites/config"
	cfg.path == site.path
	cfg_name := cfg.resource.name
	startswith(cfg_name, sprintf("%s/", [site.resource.name]))
}

_site_has_auth_enabled(site) if {
	some cfg in arm.resources("Microsoft.Web/sites/config")
	_config_matches_site(cfg, site)
	_auth_config_enabled(cfg.resource)
}

findings contains finding if {
	some s in arm.resources("Microsoft.Web/sites")
	not _site_has_auth_enabled(s)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("App Service site %q does not have authentication enabled.", [s.resource.name]),
		"artifact_uri": s.path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": 1,
		"snippet": sprintf("%s/%s", [s.resource.type, s.resource.name]),
	}
}
