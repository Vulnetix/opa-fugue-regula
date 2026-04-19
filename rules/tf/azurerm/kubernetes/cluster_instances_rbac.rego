# Adapted from https://github.com/fugue/regula (FG_R00329).
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.fugue_tf_az_aks_rbac

import rego.v1

import data.vulnetix.fugue.tf

metadata := {
	"id": "FUGUE-TF-AZ-AKS-01",
	"name": "Azure Kubernetes Service instances should have RBAC enabled",
	"description": "Azure Kubernetes Service instances should have RBAC enabled. Azure Kubernetes Services has the capability to integrate Azure Active Directory users and groups into Kubernetes RBAC controls within the AKS Kubernetes API Server. This should be utilized to enable granular access to Kubernetes resources within the AKS clusters supporting RBAC controls not just of the overarching AKS instance but also the individual resources managed within Kubernetes.",
	"help_uri": "https://github.com/fugue/regula",
	"languages": ["terraform", "hcl"],
	"severity": "medium",
	"level": "warning",
	"kind": "iac",
	"cwe": ["CWE-269"],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["terraform", "azure", "kubernetes", "rbac"],
}

findings contains finding if {
	some r in tf.resources("azurerm_kubernetes_cluster")
	tf.bool_attr(r.block, "role_based_access_control_enabled") == false
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("AKS cluster %q has role_based_access_control_enabled = false.", [r.name]),
		"artifact_uri": r.path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": 1,
		"snippet": sprintf("%s.%s", [r.type, r.name]),
	}
}
