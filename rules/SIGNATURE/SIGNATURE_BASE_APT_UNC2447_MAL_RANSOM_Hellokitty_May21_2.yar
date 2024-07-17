rule SIGNATURE_BASE_APT_UNC2447_MAL_RANSOM_Hellokitty_May21_2 : FILE
{
	meta:
		description = "Detects HelloKitty Ransomware samples from UNC2447 campaign"
		author = "Florian Roth (Nextron Systems)"
		id = "82aaabc6-102a-512e-8c2a-4d6fda864c68"
		date = "2021-05-01"
		modified = "2023-12-05"
		reference = "https://www.fireeye.com/blog/threat-research/2021/04/unc2447-sombrat-and-fivehands-ransomware-sophisticated-financial-threat.html"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/apt_unc2447_sombrat.yar#L74-L99"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "1eee3a00ab3f70425d2b6bf5dc507155bf504b851ddb6515602d83d8b6a254b8"
		score = 75
		quality = 85
		tags = "FILE"
		hash1 = "10887d13dba1f83ef34e047455a04416d25a83079a7f3798ce3483e0526e3768"
		hash2 = "3ae7bedf236d4e53a33f3a3e1e80eae2d93e91b1988da2f7fcb8fde5dcc3a0e9"
		hash3 = "501487b025f25ddf1ca32deb57a2b4db43ccf6635c1edc74b9cff54ce0e5bcfe"
		hash4 = "9a7daafc56300bd94ceef23eac56a0735b63ec6b9a7a409fb5a9b63efe1aa0b0"

	strings:
		$xop1 = { 50 8d 45 f8 50 ff 75 fc ff 15 ?? ?? 42 00 3d ea 00 00 00 75 18 83 7d f8 00 }
		$s1 = "HelloKittyMutex" wide
		$s2 = "%s\\read_me_lkd.txt" wide fullword
		$s3 = "/C ping 127.0.0.1 & del %s" wide fullword
		$s4 = "(%d) [%d] %s: STOP DOUBLE PROCESS RUN" ascii fullword
		$sop1 = { 6a 00 6a 01 ff 75 fc ff 15 ?? ?? 42 00 85 c0 0f 94 c3 ff 75 fc ff 15 ?? ?? 42 00 }
		$sop2 = { 74 12 6a 00 6a 01 ff 75 fc ff 15 ?? ?? 42 00 85 c0 0f 94 c3 ff 75 fc }

	condition:
		uint16(0)==0x5a4d and filesize <600KB and 1 of ($x*) or 2 of them
}