# Adapted from https://github.com/fugue/regula (FG_R00410).
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.fugue_tf_gcp_gce_proxy_ssl_policy

import rego.v1

import data.vulnetix.fugue.tf

metadata := {
	"id": "FUGUE-TF-GCP-GCE-10",
	"name": "Load balancer HTTPS or SSL proxy SSL policies should not have weak cipher suites",
	"description": "Load balancer HTTPS or SSL proxy SSL policies should not have weak cipher suites. The TLS (Transport Layer Security) protocol secures transmission of data over the internet using standard encryption technology, and older versions (1.0, 1.1) may pose security risks. Note that the default SSL policy allows for these older versions, and we recommend that the minimum TLS version be set to 1.2.",
	"help_uri": "https://github.com/fugue/regula",
	"languages": ["terraform", "hcl"],
	"severity": "medium",
	"level": "warning",
	"kind": "iac",
	"cwe": ["CWE-327"],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["terraform", "gcp", "compute", "tls"],
}

findings contains finding if {
	some r in _proxies
	_proxy_has_invalid_policy(r)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("%s %q uses no ssl_policy or references an SSL policy with weak TLS.", [r.type, r.name]),
		"artifact_uri": r.path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": 1,
		"snippet": sprintf("%s.%s", [r.type, r.name]),
	}
}

_proxies contains p if some p in tf.resources("google_compute_target_https_proxy")

_proxies contains p if some p in tf.resources("google_compute_target_ssl_proxy")

_proxy_has_invalid_policy(proxy) if {
	not tf.has_key(proxy.block, "ssl_policy")
}

_proxy_has_invalid_policy(proxy) if {
	ref := tf.string_attr(proxy.block, "ssl_policy")
	ref != ""
}

_proxy_has_invalid_policy(proxy) if {
	some pol in tf.resources("google_compute_ssl_policy")
	tf.references(proxy.block, "google_compute_ssl_policy", pol.name)
	_ssl_policy_invalid(pol.block)
}

_ssl_policy_invalid(block) if {
	tf.string_attr(block, "profile") == "MODERN"
	_weak_tls := {"TLS_1_0", "TLS_1_1"}
	tf.string_attr(block, "min_tls_version") in _weak_tls
}

_ssl_policy_invalid(block) if {
	tf.string_attr(block, "profile") == "CUSTOM"
	_weak_features := {
		"TLS_RSA_WITH_3DES_EDE_CBC_SHA",
		"TLS_RSA_WITH_AES_128_CBC_SHA",
		"TLS_RSA_WITH_AES_128_GCM_SHA256",
		"TLS_RSA_WITH_AES_256_CBC_SHA",
		"TLS_RSA_WITH_AES_256_GCM_SHA384",
	}
	some f in tf.string_list_attr(block, "enabled_features")
	f in _weak_features
}

_ssl_policy_invalid(block) if {
	tf.string_attr(block, "profile") == "CUSTOM"
	_weak_features := {
		"TLS_RSA_WITH_3DES_EDE_CBC_SHA",
		"TLS_RSA_WITH_AES_128_CBC_SHA",
		"TLS_RSA_WITH_AES_128_GCM_SHA256",
		"TLS_RSA_WITH_AES_256_CBC_SHA",
		"TLS_RSA_WITH_AES_256_GCM_SHA384",
	}
	some f in tf.string_list_attr(block, "custom_features")
	f in _weak_features
}
