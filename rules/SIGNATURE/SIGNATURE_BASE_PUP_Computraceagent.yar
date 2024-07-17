
rule SIGNATURE_BASE_PUP_Computraceagent : FILE
{
	meta:
		description = "Absolute Computrace Agent Executable"
		author = "ASERT - Arbor Networks (slightly modified by Florian Roth)"
		id = "676f8f1e-a3b4-5d05-b13b-bd6cb0aabbbd"
		date = "2018-05-01"
		modified = "2023-12-05"
		reference = "https://asert.arbornetworks.com/lojack-becomes-a-double-agent/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/apt_fancybear_computrace_agent.yar#L1-L14"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "65e964e68be1e286ab3aa39677e250cf5994a7a08d0f6db286c0260cf77d6c48"
		score = 75
		quality = 85
		tags = "FILE"

	strings:
		$a = { D1 E0 F5 8B 4D 0C 83 D1 00 8B EC FF 33 83 C3 04 }
		$b1 = { 72 70 63 6E 65 74 70 2E 65 78 65 00 72 70 63 6E 65 74 70 00 }
		$b2 = { 54 61 67 49 64 00 }

	condition:
		uint16(0)==0x5a4d and filesize <40KB and ($a or ($b1 and $b2))
}