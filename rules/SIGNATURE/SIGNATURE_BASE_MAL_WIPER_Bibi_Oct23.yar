rule SIGNATURE_BASE_MAL_WIPER_Bibi_Oct23 : FILE
{
	meta:
		description = "Detects BiBi wiper samples for Windows and Linux"
		author = "Florian Roth"
		id = "e1ea8016-e074-5208-8c98-54922bbcc407"
		date = "2023-11-01"
		modified = "2023-12-05"
		reference = "https://x.com/ESETresearch/status/1719437301900595444?s=20"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/mal_bibi_wiper_oct23.yar#L24-L47"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "c22dc994005f91f81d0e8e5f8d400b12ecd28336866bc62b8527e104f6339372"
		score = 75
		quality = 85
		tags = "FILE"
		hash1 = "23bae09b5699c2d5c4cb1b8aa908a3af898b00f88f06e021edcb16d7d558efad"
		hash2 = "40417e937cd244b2f928150cae6fa0eff5551fdb401ea072f6ecdda67a747e17"

	strings:
		$s1 = "send attempt while closed" ascii fullword
		$s2 = "[+] CPU cores: %d, Threads: %d" ascii fullword
		$s3 = "[+] Stats: %d | %d" ascii fullword
		$opw1 = { 33 c0 88 45 48 b8 01 00 00 00 86 45 48 45 8b f5 48 8d 3d de f5 ff ff 0f 57 c9 f3 0f 7f 4d b8 }
		$opw2 = { 2d ce b5 00 00 c5 fa e6 f5 e9 40 fe ff ff 0f 1f 44 00 00 75 2e c5 fb 10 0d 26 b4 00 00 44 8b 05 5f b6 00 00 e8 ca 0d 00 00 }
		$opl1 = { 4c 8d 44 24 08 48 89 f7 48 ff c2 48 83 c6 04 e8 c7 fb ff ff 41 89 c1 0f b6 42 ff 41 0f af c1 }
		$opl2 = { e8 6f fb ff ff 49 8d 78 f8 89 c0 48 01 c2 48 89 15 09 fb 24 00 e8 5a fb ff ff 49 8d 78 fc 6b f0 06 }

	condition:
		( uint16(0)==0x5a4d or uint16(0)==0x457f) and filesize <4000KB and 2 of them
}