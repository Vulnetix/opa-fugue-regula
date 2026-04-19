# Adapted from https://github.com/fugue/regula (FG_R00197).
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.fugue_arm_vm_unattached_disk_encryption

import rego.v1

import data.vulnetix.fugue.arm

metadata := {
	"id": "FUGUE-ARM-VM-02",
	"name": "Virtual Machines unattached disks should be encrypted",
	"description": "Encrypting the IaaS VM's disks ensures that its entire content is fully unrecoverable without a key and thus protects the volume from unwarranted reads.",
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

_disk_encrypted(disk) if {
	disk.properties.encryptionSettingsCollection.enabled == true
}

_disk_encrypted(disk) if {
	_ := disk.properties.encryption.diskEncryptionSetId
}

_disk_encrypted(disk) if {
	disk.properties.encryption.type
}

# "Attached" heuristic: disk name appears as an os disk or data disk reference
# in any VM's storageProfile.
_is_attached(disk_name) if {
	some vm in arm.resources("Microsoft.Compute/virtualMachines")
	ref := object.get(object.get(vm.resource.properties.storageProfile.osDisk, "managedDisk", {}), "id", "")
	contains(ref, disk_name)
}

_is_attached(disk_name) if {
	some vm in arm.resources("Microsoft.Compute/virtualMachines")
	some d in object.get(vm.resource.properties.storageProfile, "dataDisks", [])
	ref := object.get(object.get(d, "managedDisk", {}), "id", "")
	contains(ref, disk_name)
}

findings contains finding if {
	some d in arm.resources("Microsoft.Compute/disks")
	not _is_attached(d.resource.name)
	not _disk_encrypted(d.resource)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Unattached disk %q is not encrypted.", [d.resource.name]),
		"artifact_uri": d.path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": 1,
		"snippet": sprintf("%s/%s", [d.resource.type, d.resource.name]),
	}
}
