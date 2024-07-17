
rule SIGNATURE_BASE_APT_UNC2447_MAL_SOMBRAT_May21_1 : FILE
{
	meta:
		description = "Detects SombRAT samples from UNC2447 campaign"
		author = "Florian Roth (Nextron Systems)"
		id = "78b46bed-4fd4-596f-bba7-12243f467af3"
		date = "2021-05-01"
		modified = "2023-01-07"
		reference = "https://www.fireeye.com/blog/threat-research/2021/04/unc2447-sombrat-and-fivehands-ransomware-sophisticated-financial-threat.html"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/apt_unc2447_sombrat.yar#L2-L36"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "6f2572745cbd68c5f2be5c64b160d2513938daba6da57523012491acc63cfee4"
		score = 75
		quality = 85
		tags = "FILE"
		hash1 = "61e286c62e556ac79b01c17357176e58efb67d86c5d17407e128094c3151f7f9"
		hash2 = "99baffcd7a6b939b72c99af7c1e88523a50053ab966a079d9bf268aff884426e"

	strings:
		$x1 = "~arungvc" ascii fullword
		$s1 = "plugin64_" ascii
		$s2 = "0xUnknown" ascii fullword
		$s3 = "b%x.%s" ascii fullword
		$s4 = "/news" ascii
		$sc1 = { 00 73 00 65 00 72 00 76 00 69 00 63 00 65 00 73
               00 2E 00 65 00 78 00 65 00 00 00 00 00 00 00 00
               00 49 73 57 6F 77 36 34 50 72 6F 63 65 73 73 00
               00 6B 00 65 00 72 00 6E 00 65 00 6C 00 33 00 32
               00 00 00 00 00 00 00 00 00 47 00 6C 00 6F 00 62
               00 61 00 6C 00 5C 00 25 00 73 }
		$op1 = { 66 90 0f b6 45 80 32 44 0d 81 34 de 88 44 0d 81 48 ff c1 48 83 f9 19 72 e9 }
		$op2 = { 48 8b d0 66 0f 6f 05 ?1 ?? 0? 00 f3 0f 7f 44 24 68 66 89 7c 24 58 41 b8 10 00 00 00 4c 39 40 10 4c 0f 42 40 10 48 83 78 18 08 }
		$op3 = { 49 f7 b0 a0 00 00 00 42 0f b6 04 0a 41 30 44 33 fe 48 83 79 18 10 72 03 48 8b 09 33 d2 b8 05 00 00 00 }

	condition:
		uint16(0)==0x5a4d and filesize <3000KB and ((1 of ($x*) and 1 of ($s*)) or 3 of them ) or 5 of them
}