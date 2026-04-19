# Adapted from https://github.com/fugue/regula (FG_R00500).
# Ported to the Vulnetix Rego input schema (input.file_contents).
# Simplified: text-scans aws_wafv2_web_acl for managed_rule_group_statement referencing AWSManagedRulesKnownBadInputsRuleSet.

package vulnetix.rules.fugue_tf_aws_waf_01

import rego.v1

import data.vulnetix.fugue.tf

metadata := {
	"id": "FUGUE-TF-AWS-WAF-01",
	"name": "WAFv2 web ACLs should include the AWSManagedRulesKnownBadInputsRuleSet managed rule group",
	"description": "The 'Known bad inputs' managed rule group blocks request patterns that are invalid or known to be associated with vulnerabilities such as Log4j.",
	"help_uri": "https://github.com/fugue/regula",
	"languages": ["terraform", "hcl"],
	"severity": "critical",
	"level": "error",
	"kind": "iac",
	"cwe": ["CWE-693"],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["terraform", "aws", "waf"],
}

findings contains finding if {
	some w in tf.resources("aws_wafv2_web_acl")
	not _has_known_bad_inputs(w.block)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("aws_wafv2_web_acl %q does not include the AWSManagedRulesKnownBadInputsRuleSet managed rule group.", [w.name]),
		"artifact_uri": w.path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": 1,
		"snippet": sprintf("%s.%s", [w.type, w.name]),
	}
}

_has_known_bad_inputs(block) if {
	regex.match(`(?s)managed_rule_group_statement[\s\S]*?name\s*=\s*"AWSManagedRulesKnownBadInputsRuleSet"[\s\S]*?vendor_name\s*=\s*"AWS"`, block)
}

_has_known_bad_inputs(block) if {
	regex.match(`(?s)managed_rule_group_statement[\s\S]*?vendor_name\s*=\s*"AWS"[\s\S]*?name\s*=\s*"AWSManagedRulesKnownBadInputsRuleSet"`, block)
}
