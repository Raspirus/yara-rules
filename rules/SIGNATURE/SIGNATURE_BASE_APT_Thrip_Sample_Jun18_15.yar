import "pe"


rule SIGNATURE_BASE_APT_Thrip_Sample_Jun18_15 : FILE
{
	meta:
		description = "Detects sample found in Thrip report by Symantec "
		author = "Florian Roth (Nextron Systems)"
		id = "fd8aa404-4c12-5c8f-a952-a143da858b9b"
		date = "2018-06-21"
		modified = "2023-12-05"
		reference = "https://www.symantec.com/blogs/threat-intelligence/thrip-hits-satellite-telecoms-defense-targets "
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/apt_thrip.yar#L278-L299"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "22769d215e52965f48eb3455b39fbd8f8ce950a67f8132612d42b78fde9822a5"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "231c569f11460a12b171f131c40a6f25d8416954b35c28ae184aba8a649d9786"

	strings:
		$s1 = "%s\\cmd.exe /c %s" fullword ascii
		$s2 = "CryptBase.dll" fullword ascii
		$s3 = "gupdate.exe" fullword ascii
		$s4 = "wusa.exe" fullword ascii
		$s5 = " %s %s /quiet /extract:%s\\%s\\" ascii
		$s6 = "%s%s.dll.cab" fullword ascii
		$s7 = "%s\\%s\\%s%s %s" fullword ascii
		$s8 = "%s\\%s\\%s%s" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <200KB and (pe.imphash()=="f6ec70a295000ab0a753aa708e9439b4" or 6 of them )
}