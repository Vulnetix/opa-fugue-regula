# Adapted from https://github.com/fugue/regula (FG_R00435).
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.fugue_tf_gcp_sql_no_public_ip

import rego.v1

import data.vulnetix.fugue.tf

metadata := {
	"id": "FUGUE-TF-GCP-SQL-04",
	"name": "SQL database instances should not have public IPs",
	"description": "SQL database instances should not have public IPs. SQL database instances with public IP addresses are directly accessible by hosts on the Internet. To minimize its attack surface, a database server should be configured with private IP addresses. Private addresses provide better security because of intermediary firewall or NAT devices.",
	"help_uri": "https://github.com/fugue/regula",
	"languages": ["terraform", "hcl"],
	"severity": "medium",
	"level": "warning",
	"kind": "iac",
	"cwe": ["CWE-284"],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["terraform", "gcp", "sql", "networking"],
}

findings contains finding if {
	some r in tf.resources("google_sql_database_instance")
	_has_public_ip(r.block)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("google_sql_database_instance %q has ipv4_enabled = true (public IP).", [r.name]),
		"artifact_uri": r.path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": 1,
		"snippet": sprintf("%s.%s", [r.type, r.name]),
	}
}

_has_public_ip(block) if {
	some settings in tf.sub_blocks(block, "settings")
	some ip in tf.sub_blocks(settings, "ip_configuration")
	tf.bool_attr(ip, "ipv4_enabled") == true
}
