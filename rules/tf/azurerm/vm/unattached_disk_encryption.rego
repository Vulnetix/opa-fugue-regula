# Adapted from https://github.com/fugue/regula (FG_R00197).
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.fugue_tf_az_vm_unattached_disk_encryption

import rego.v1

import data.vulnetix.fugue.tf

metadata := {
	"id": "FUGUE-TF-AZ-VM-02",
	"name": "Virtual Machines unattached disks should be encrypted",
	"description": "Virtual Machines unattached disks should be encrypted. Encrypting the IaaS VM's disks ensures that its entire content is fully unrecoverable without a key and thus protects the volume from unwarranted reads.",
	"help_uri": "https://github.com/fugue/regula",
	"languages": ["terraform", "hcl"],
	"severity": "high",
	"level": "error",
	"kind": "iac",
	"cwe": ["CWE-311"],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["terraform", "azure", "vm", "encryption"],
}

findings contains finding if {
	some md in tf.resources("azurerm_managed_disk")
	not _is_attached(md.name)
	not _disk_is_encrypted(md.block)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Unattached managed disk %q is not encrypted.", [md.name]),
		"artifact_uri": md.path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": 1,
		"snippet": sprintf("%s.%s", [md.type, md.name]),
	}
}

_is_attached(md_name) if {
	some vm in tf.resources("azurerm_virtual_machine")
	some sdd in tf.sub_blocks(vm.block, "storage_data_disk")
	tf.references(sdd, "azurerm_managed_disk", md_name)
}

_is_attached(md_name) if {
	some vm in tf.resources("azurerm_virtual_machine")
	some os in tf.sub_blocks(vm.block, "storage_os_disk")
	tf.references(os, "azurerm_managed_disk", md_name)
}

_is_attached(md_name) if {
	some att in tf.resources("azurerm_virtual_machine_data_disk_attachment")
	tf.references(att.block, "azurerm_managed_disk", md_name)
}

_disk_is_encrypted(block) if {
	some es in tf.sub_blocks(block, "encryption_settings")
	tf.bool_attr(es, "enabled") == true
}

_disk_is_encrypted(block) if {
	v := tf.string_attr(block, "disk_encryption_set_id")
	count(v) > 0
}

_disk_is_encrypted(block) if tf.has_key(block, "disk_encryption_set_id")
