# Adapted from https://github.com/fugue/regula (FG_R00376).
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.fugue_cfn_api_gateway_v2_custom_domain_name

import rego.v1

import data.vulnetix.fugue.cfn

metadata := {
	"id": "FUGUE-CFN-API-02",
	"name": "API Gateway v2 custom domains should use TLS 1.2+",
	"description": "API Gateway v2 custom domains should use secure TLS protocol versions (1.2 and above). Versions prior to TLS 1.2 are deprecated and usage may pose security risks.",
	"help_uri": "https://github.com/fugue/regula",
	"languages": ["yaml", "json"],
	"severity": "medium",
	"level": "warning",
	"kind": "iac",
	"cwe": ["CWE-327"],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["cloudformation", "aws", "api-gateway", "tls"],
}

_invalid_settings := {"TLS_1_0"}

_valid_domain_config(domain_config) if {
	sp := domain_config.SecurityPolicy
	sp != null
	not _invalid_settings[sp]
}

_domain_name_valid(props) if {
	configs := props.DomainNameConfigurations
	count(configs) > 0
	some c in configs
	_valid_domain_config(c)
}

findings contains finding if {
	some r in cfn.resources("AWS::ApiGatewayV2::DomainName")
	props := cfn.properties(r)
	not _domain_name_valid(props)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("AWS::ApiGatewayV2::DomainName %q has no DomainNameConfigurations with a secure TLS SecurityPolicy.", [r.logical_id]),
		"artifact_uri": r.path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": 1,
		"snippet": sprintf("AWS::ApiGatewayV2::DomainName/%s", [r.logical_id]),
	}
}

findings contains finding if {
	some r in cfn.resources("AWS::Serverless::HttpApi")
	props := cfn.properties(r)
	domain := props.Domain
	domain != null
	not _valid_domain_config(domain)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("AWS::Serverless::HttpApi %q Domain uses a deprecated or missing SecurityPolicy (TLS).", [r.logical_id]),
		"artifact_uri": r.path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": 1,
		"snippet": sprintf("AWS::Serverless::HttpApi/%s", [r.logical_id]),
	}
}
