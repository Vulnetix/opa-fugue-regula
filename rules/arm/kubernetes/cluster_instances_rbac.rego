# Adapted from https://github.com/fugue/regula (FG_R00329).
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.fugue_arm_kubernetes_cluster_instances_rbac

import rego.v1

import data.vulnetix.fugue.arm

metadata := {
	"id": "FUGUE-ARM-K8S-01",
	"name": "Azure Kubernetes Service instances should have RBAC enabled",
	"description": "Azure Kubernetes Services has the capability to integrate Azure Active Directory users and groups into Kubernetes RBAC controls within the AKS Kubernetes API Server. This should be utilized to enable granular access to Kubernetes resources within the AKS clusters supporting RBAC controls not just of the overarching AKS instance but also the individual resources managed within Kubernetes.",
	"help_uri": "https://github.com/fugue/regula",
	"languages": ["json"],
	"severity": "medium",
	"level": "warning",
	"kind": "iac",
	"cwe": ["CWE-269"],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["arm", "azure", "aks", "rbac"],
}

findings contains finding if {
	some r in arm.resources("Microsoft.ContainerService/managedClusters")
	not object.get(r.resource.properties, "enableRBAC", false) == true
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("AKS cluster %q does not have RBAC enabled.", [r.resource.name]),
		"artifact_uri": r.path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": 1,
		"snippet": sprintf("%s/%s", [r.resource.type, r.resource.name]),
	}
}
