import "pe"


rule SIGNATURE_BASE_APT_TA18_149A_Joanap_Sample1 : FILE
{
	meta:
		description = "Detects malware from TA18-149A report by US-CERT"
		author = "Florian Roth (Nextron Systems)"
		id = "a3a4f9a6-367d-5d99-bffb-f4ff03fa4a09"
		date = "2018-05-30"
		modified = "2023-12-05"
		reference = "https://www.us-cert.gov/ncas/alerts/TA18-149A"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/apt_ta18_149A.yar#L13-L34"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "746c74713ac52f62d5a5c41d2c9321e00481a45aa2c23f1695fab0f5b6d5dfb4"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "ea46ed5aed900cd9f01156a1cd446cbb3e10191f9f980e9f710ea1c20440c781"

	strings:
		$x1 = "cmd.exe /q /c net share adnim$" ascii
		$x2 = "\\\\%s\\adnim$\\system32\\%s" fullword ascii
		$s1 = "SMB_Dll.dll" fullword ascii
		$s2 = "%s User or Password is not correct!" fullword ascii
		$s3 = "perfw06.dat" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <300KB and (pe.imphash()=="f0087d7b90876a2769f2229c6789fcf3" or 1 of ($x*) or 2 of them )
}