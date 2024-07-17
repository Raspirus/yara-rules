rule SIGNATURE_BASE_MAL_Winnti_Sample_May18_1 : FILE
{
	meta:
		description = "Detects malware sample from Burning Umbrella report - Generic Winnti Rule"
		author = "Florian Roth (Nextron Systems)"
		id = "c2f3339e-269f-5a51-8db6-06e54a707b3a"
		date = "2018-05-04"
		modified = "2023-12-05"
		reference = "https://401trg.pw/burning-umbrella/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/apt_winnti_burning_umbrella.yar#L426-L440"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "e235396de278120cbc4700f239c41e7f21e97ba111c07022ae505de540dda2bc"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "528d9eaaac67716e6b37dd562770190318c8766fa1b2f33c0974f7d5f6725d41"

	strings:
		$s1 = "wireshark" fullword wide
		$s2 = "procexp" fullword wide

	condition:
		uint16(0)==0x5a4d and filesize <100KB and all of them
}