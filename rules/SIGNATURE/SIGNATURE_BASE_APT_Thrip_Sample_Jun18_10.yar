rule SIGNATURE_BASE_APT_Thrip_Sample_Jun18_10 : FILE
{
	meta:
		description = "Detects sample found in Thrip report by Symantec "
		author = "Florian Roth (Nextron Systems)"
		id = "3307ca18-59fb-5400-b51e-c4f4aa99e592"
		date = "2018-06-21"
		modified = "2023-12-05"
		reference = "https://www.symantec.com/blogs/threat-intelligence/thrip-hits-satellite-telecoms-defense-targets "
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/apt_thrip.yar#L172-L189"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "79a8dfd63e96ccc9259272476e364e53b841b42255a2a5f3b9f93e91caa5d1c2"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "350d2a6f8e6a4969ffbf75d9f9aae99e7b3a8cd8708fd66f977e07d7fbf842e3"

	strings:
		$x1 = "!This Program cannot be run in DOS mode." fullword ascii
		$x2 = "!this program cannot be run in dos mode." fullword ascii
		$s1 = "svchost.dll" fullword ascii
		$s2 = "constructor or from DllMain." fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <200KB and ($x1 or 2 of them )
}