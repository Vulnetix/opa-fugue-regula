# Adapted from https://github.com/fugue/regula (FG_R00196).
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.fugue_arm_vm_data_disk_encryption

import rego.v1

import data.vulnetix.fugue.arm

metadata := {
	"id": "FUGUE-ARM-VM-01",
	"name": "Virtual Machines data disks (non-boot volumes) should be encrypted",
	"description": "Encrypting the IaaS VM's Data disks ensures that its entire content is fully unrecoverable without a key and thus protects the volume from unwarranted reads.",
	"help_uri": "https://github.com/fugue/regula",
	"languages": ["json"],
	"severity": "high",
	"level": "error",
	"kind": "iac",
	"cwe": ["CWE-311"],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["arm", "azure", "vm", "encryption-at-rest"],
}

# Disk is encrypted if encryptionSettingsCollection is enabled, OR the disk has
# `encryption` with a diskEncryptionSetId.
_disk_encrypted(disk) if {
	disk.properties.encryptionSettingsCollection.enabled == true
}

_disk_encrypted(disk) if {
	_ := disk.properties.encryption.diskEncryptionSetId
}

_disk_encrypted(disk) if {
	disk.properties.encryption.type
}

# A data disk: Microsoft.Compute/disks whose id is referenced from a VM's
# dataDisks[].managedDisk.id. Simplification: without cloud cross-ref we flag
# all Microsoft.Compute/disks that are not encrypted and are not the VM's OS
# disk. We consider a disk a "data disk" when its name matches one referenced
# by any VM's storageProfile.dataDisks, OR conservatively, any unencrypted
# disk resource that is NOT the OS disk.
_referenced_as_data_disk(disk_name) if {
	some vm in arm.resources("Microsoft.Compute/virtualMachines")
	some d in object.get(vm.resource.properties.storageProfile, "dataDisks", [])
	ref := object.get(object.get(d, "managedDisk", {}), "id", "")
	contains(ref, disk_name)
}

findings contains finding if {
	some d in arm.resources("Microsoft.Compute/disks")
	_referenced_as_data_disk(d.resource.name)
	not _disk_encrypted(d.resource)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Data disk %q is not encrypted.", [d.resource.name]),
		"artifact_uri": d.path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": 1,
		"snippet": sprintf("%s/%s", [d.resource.type, d.resource.name]),
	}
}

# Inlined (unmanaged) data disks have no encryption settings — flag the VM.
_vm_has_unmanaged_data_disk(vm) if {
	some d in object.get(vm.resource.properties.storageProfile, "dataDisks", [])
	not object.get(object.get(d, "managedDisk", {}), "id", "")
}

findings contains finding if {
	some vm in arm.resources("Microsoft.Compute/virtualMachines")
	_vm_has_unmanaged_data_disk(vm)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("VM %q has inlined (unmanaged) data disks that cannot be encrypted.", [vm.resource.name]),
		"artifact_uri": vm.path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": 1,
		"snippet": sprintf("%s/%s", [vm.resource.type, vm.resource.name]),
	}
}
