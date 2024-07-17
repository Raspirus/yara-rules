import "pe"


rule SIGNATURE_BASE_APT_Thrip_Sample_Jun18_4 : FILE
{
	meta:
		description = "Detects sample found in Thrip report by Symantec "
		author = "Florian Roth (Nextron Systems)"
		id = "9dcfcdbd-d18f-5eba-a10c-95686f010f23"
		date = "2018-06-21"
		modified = "2023-12-05"
		reference = "https://www.symantec.com/blogs/threat-intelligence/thrip-hits-satellite-telecoms-defense-targets "
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/apt_thrip.yar#L64-L85"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "f258070054a29cbec0876536d295b85c7bd9f23988d1e0fc2ba58660b0796716"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "6b236d3fc54d36e6dc2a26299f6ded597058fed7c9099f1a37716c5e4b162abc"

	strings:
		$s1 = "\\system32\\wbem\\tmf\\caches_version.db" ascii
		$s2 = "ProcessName No Access" fullword ascii
		$s3 = "Hwnd of Process NULL" fullword ascii
		$s4 = "*********The new session is be opening:(%d)**********" fullword ascii
		$s5 = "[EXECUTE]" fullword ascii
		$s6 = "/------------------------------------------------------------------------" fullword ascii
		$s7 = "constructor or from DllMain." fullword ascii
		$s8 = "Time:%d-%d-%d %d:%d:%d" fullword ascii
		$s9 = "\\info.config" ascii

	condition:
		uint16(0)==0x5a4d and filesize <400KB and 5 of them
}