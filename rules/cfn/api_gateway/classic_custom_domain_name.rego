# Adapted from https://github.com/fugue/regula (FG_R00375).
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.fugue_cfn_api_gateway_classic_custom_domain_name

import rego.v1

import data.vulnetix.fugue.cfn

metadata := {
	"id": "FUGUE-CFN-API-01",
	"name": "API Gateway classic custom domains should use TLS 1.2+",
	"description": "API Gateway classic custom domains should use secure TLS protocol versions (1.2 and above). Versions prior to TLS 1.2 are deprecated and usage may pose security risks.",
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

_valid_domain(domain) if {
	sp := domain.SecurityPolicy
	sp != null
	not _invalid_settings[sp]
}

findings contains finding if {
	some r in cfn.resources("AWS::ApiGateway::DomainName")
	props := cfn.properties(r)
	not _valid_domain(props)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("AWS::ApiGateway::DomainName %q uses a deprecated or missing SecurityPolicy (TLS).", [r.logical_id]),
		"artifact_uri": r.path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": 1,
		"snippet": sprintf("AWS::ApiGateway::DomainName/%s", [r.logical_id]),
	}
}

findings contains finding if {
	some r in cfn.resources("AWS::Serverless::Api")
	props := cfn.properties(r)
	domain := props.Domain
	domain != null
	not _valid_domain(domain)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("AWS::Serverless::Api %q uses a deprecated or missing SecurityPolicy (TLS).", [r.logical_id]),
		"artifact_uri": r.path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": 1,
		"snippet": sprintf("AWS::Serverless::Api/%s", [r.logical_id]),
	}
}
