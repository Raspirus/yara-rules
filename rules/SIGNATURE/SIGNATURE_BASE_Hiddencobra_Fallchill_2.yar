import "pe"


rule SIGNATURE_BASE_Hiddencobra_Fallchill_2 : FILE
{
	meta:
		description = "Auto-generated rule"
		author = "Florian Roth (Nextron Systems)"
		id = "c343e8e4-0785-5a47-99c1-98b189f4aaa0"
		date = "2017-11-15"
		modified = "2023-12-05"
		reference = "https://www.us-cert.gov/ncas/alerts/TA17-318A"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/apt_ta17_318A.yar#L79-L97"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "ab421bea251ed3fda4304cd180e5c31f7ae55d3d8b26d6cf5f1cf11bacee9b8d"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "0a118eb23399000d148186b9079fa59caf4c3faa7e7a8f91533e467ac9b6ff41"

	strings:
		$s1 = "%s\\%s.dll" fullword wide
		$s2 = "yurdkr.dll" fullword ascii
		$s3 = "c%sd.e%sc %s > \"%s\" 2>&1" fullword wide

	condition:
		uint16(0)==0x5a4d and filesize <500KB and (pe.imphash()=="cb36dcb9909e29a38c387b8a87e7e4ed" or (2 of them ))
}