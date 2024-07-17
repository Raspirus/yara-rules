rule SIGNATURE_BASE_APT_UNC2447_MAL_RANSOM_Hellokitty_May21_1 : FILE
{
	meta:
		description = "Detects HelloKitty Ransomware samples from UNC2447 campaign"
		author = "Florian Roth (Nextron Systems)"
		id = "c84b2430-dcf1-5a80-96a0-02d292ea386b"
		date = "2021-05-01"
		modified = "2023-12-05"
		reference = "https://www.fireeye.com/blog/threat-research/2021/04/unc2447-sombrat-and-fivehands-ransomware-sophisticated-financial-threat.html"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/apt_unc2447_sombrat.yar#L38-L72"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "acc0ab5502d53c6e22c8650c29c5459a6106f33c398e4efcd963f54971a0c870"
		score = 75
		quality = 85
		tags = "FILE"
		hash1 = "02a08b994265901a649f1bcf6772bc06df2eb51eb09906af9fd0f4a8103e9851"
		hash2 = "0e5f7737704c8f25b2b8157561be54a463057cd4d79c7e016c30a1cf6590a85c"
		hash3 = "52dace403e8f9b4f7ea20c0c3565fa11b6953b404a7d49d63af237a57b36fd2a"
		hash4 = "7be901c5f7ffeb8f99e4f5813c259d0227335680380ed06df03fb836a041cb06"
		hash5 = "947e357bfdfe411be6c97af6559fd1cdc5c9d6f5cea122bf174d124ee03d2de8"
		hash6 = "9a7daafc56300bd94ceef23eac56a0735b63ec6b9a7a409fb5a9b63efe1aa0b0"
		hash7 = "a147945635d5bd0fa832c9b55bc3ebcea7a7787e8f89b98a44279f8eddda2a77"
		hash8 = "bade05a30aba181ffbe4325c1ba6c76ef9e02cbe41a4190bd3671152c51c4a7b"
		hash9 = "c2498845ed4b287fd0f95528926c8ee620ef0cbb5b27865b2007d6379ffe4323"
		hash10 = "dc007e71085297883ca68a919e37687427b7e6db0c24ca014c148f226d8dd98f"
		hash11 = "ef614b456ca4eaa8156a895f450577600ad41bd553b4512ae6abf3fb8b5eb04e"

	strings:
		$xop1 = { 8b 45 08 8b 75 f4 fe 85 f7 fd ff ff 0f 11 44 05 b4 83 c0 10 89 45 08 83 f8 30 7c 82 }
		$xop2 = { 81 c3 dc a9 b0 5c c1 c9 0b 33 c8 89 55 a0 8b c7 8b 7d e0 c1 c8 06 33 f7 }
		$s1 = "select * from Win32_ShadowCopy" wide fullword
		$s2 = "bootfont.bin" wide fullword
		$s3 = "DECRYPT_NOTE.txt" wide fullword
		$s4 = ".onion" wide
		$sop1 = { 8b f9 0f 57 c0 68 18 01 00 00 6a 00 0f 11 45 dc 8d 5f 20 53 0f 11 45 ec }
		$sop2 = { 56 57 8b f9 0f 57 c0 68 18 01 00 00 6a 00 0f 11 45 dc 8d 5f 20 }
		$sop3 = { 57 8b f9 0f 57 c0 68 18 01 00 00 6a 00 0f 11 45 dc 8d 5f 20 53 }

	condition:
		uint16(0)==0x5a4d and filesize <800KB and 1 of ($x*) or 3 of them
}