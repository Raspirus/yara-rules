rule SIGNATURE_BASE_APT_MAL_LNX_Redmenshen_Bpfdoor_Controller_May22_3 : FILE
{
	meta:
		description = "Detects BPFDoor implants used by Chinese actor Red Menshen"
		author = "Florian Roth (Nextron Systems)"
		id = "91c2153a-a6e0-529e-852c-61f799838798"
		date = "2022-05-08"
		modified = "2023-12-05"
		reference = "https://doublepulsar.com/bpfdoor-an-active-chinese-global-surveillance-tool-54b078f1a896"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/mal_lnx_implant_may22.yar#L102-L119"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "afec0bfeddf5c5c2abc1a3173f636c385437e5d7c0b68665f6274011113a6a9c"
		score = 85
		quality = 85
		tags = "FILE"
		hash1 = "144526d30ae747982079d5d340d1ff116a7963aba2e3ed589e7ebc297ba0c1b3"
		hash2 = "fa0defdabd9fd43fe2ef1ec33574ea1af1290bd3d763fdb2bed443f2bd996d73"

	strings:
		$s1 = "hald-addon-acpi: listening on acpi kernel interface /proc/acpi/event" ascii fullword
		$s2 = "/sbin/mingetty /dev" ascii fullword
		$s3 = "pickup -l -t fifo -u" ascii fullword

	condition:
		uint16(0)==0x457f and filesize <200KB and 2 of them or all of them
}