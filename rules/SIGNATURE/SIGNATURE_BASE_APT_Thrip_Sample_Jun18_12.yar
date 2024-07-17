import "pe"


rule SIGNATURE_BASE_APT_Thrip_Sample_Jun18_12 : FILE
{
	meta:
		description = "Detects sample found in Thrip report by Symantec "
		author = "Florian Roth (Nextron Systems)"
		id = "b24b8042-b6a3-5af8-9fcf-6d042bdb9524"
		date = "2018-06-21"
		modified = "2023-12-05"
		reference = "https://www.symantec.com/blogs/threat-intelligence/thrip-hits-satellite-telecoms-defense-targets "
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/apt_thrip.yar#L212-L234"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "49357a34f3b1d0bb86d1c6ddfa6a6c3b92bfafaebd050d835c0a902199a2121b"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "33c01d3266fe6a70e8785efaf10208f869ae58a17fd9cdb2c6995324c9a01062"

	strings:
		$s1 = "pGlobal->nOSType==64--%s\\cmd.exe %s" fullword ascii
		$s2 = "httpcom.log" fullword ascii
		$s3 = "\\CryptBase.dll" ascii
		$s4 = "gupdate.exe" fullword ascii
		$s5 = "wusa.exe" fullword ascii
		$s6 = " %s %s /quiet /extract:%s\\%s\\" ascii
		$s7 = "%s%s.dll.cab" fullword ascii
		$s8 = "/c %s\\%s\\%s%s %s" fullword ascii
		$s9 = "ReleaseEvildll" fullword ascii
		$s0 = "%s\\%s\\%s%s" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <100KB and 6 of them
}