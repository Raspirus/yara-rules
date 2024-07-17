import "pe"


rule SIGNATURE_BASE_Slingshot_APT_Ring0_Loader : FILE
{
	meta:
		description = "Detects malware from Slingshot APT"
		author = "Florian Roth (Nextron Systems)"
		id = "b5301a45-a4ec-5e56-a990-bc6300ee6365"
		date = "2018-03-09"
		modified = "2023-12-05"
		reference = "https://securelist.com/apt-slingshot/84312/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/apt_slingshot.yar#L40-L58"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "c231158e44de01585e9fb4bd9768b388016972e2026e049070cdc6cd35362609"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s1 = " -> Missing element in DataDir -- cannot install" ascii
		$s2 = " -> Primary loader not present in the DataDir" ascii
		$s3 = "\\\\.\\amxpci" fullword ascii
		$s4 = " -> [Goad] ERROR in CreateFile:" fullword ascii
		$s5 = "\\\\.\\Sandra" fullword ascii
		$s6 = " -> [Sandra] RingZeroCode" fullword ascii
		$s7 = " -> [Sandra] Value from IOCTL_RDMSR:" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <3000KB and 1 of them
}