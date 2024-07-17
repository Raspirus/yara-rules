import "pe"


rule SIGNATURE_BASE_APT_Thrip_Sample_Jun18_2 : FILE
{
	meta:
		description = "Detects sample found in Thrip report by Symantec "
		author = "Florian Roth (Nextron Systems)"
		id = "bc1cfcc8-64a0-5da0-8ff7-147da8a3af0b"
		date = "2018-06-21"
		modified = "2023-12-05"
		reference = "https://www.symantec.com/blogs/threat-intelligence/thrip-hits-satellite-telecoms-defense-targets "
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/apt_thrip.yar#L31-L46"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "ddd3dee11e25ea40fa3cc578c6a836ea850359a5914d5eb5d16ea4340827b91b"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "1fc9f7065856cd8dc99b6f46cf0953adf90e2c42a3b65374bf7b50274fb200cc"

	strings:
		$s1 = "C:\\WINDOWS\\system32\\sysprep\\cryptbase.dll" fullword ascii
		$s2 = "ProbeScriptFint" fullword wide
		$s3 = "C:\\WINDOWS\\system32\\cmd.exe" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <60KB and all of them
}