rule SIGNATURE_BASE_APT_Thrip_Sample_Jun18_1 : FILE
{
	meta:
		description = "Detects sample found in Thrip report by Symantec "
		author = "Florian Roth (Nextron Systems)"
		id = "5b506069-8185-5dc0-bf64-90646f6bab6b"
		date = "2018-06-21"
		modified = "2023-12-05"
		reference = "https://www.symantec.com/blogs/threat-intelligence/thrip-hits-satellite-telecoms-defense-targets "
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/apt_thrip.yar#L13-L29"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "6e94111abe83aa500bfa35a3a7c2d43c3ed4011bc540401f047e84cfc27204ca"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "59509a17d516813350fe1683ca6b9727bd96dd81ce3435484a5a53b472ff4ae9"

	strings:
		$s1 = "idocback.dll" fullword ascii
		$s2 = "constructor or from DllMain." fullword ascii
		$s3 = "appmgmt" fullword ascii
		$s4 = "chksrv" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <200KB and all of them
}