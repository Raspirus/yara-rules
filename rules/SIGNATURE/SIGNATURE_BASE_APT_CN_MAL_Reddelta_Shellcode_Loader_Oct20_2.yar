rule SIGNATURE_BASE_APT_CN_MAL_Reddelta_Shellcode_Loader_Oct20_2 : FILE
{
	meta:
		description = "Detects Red Delta samples"
		author = "Florian Roth (Nextron Systems)"
		id = "acb1024a-64af-51ac-84c8-7fe9a5bd4538"
		date = "2020-10-14"
		modified = "2023-12-05"
		reference = "https://twitter.com/JAMESWT_MHT/status/1316387482708119556"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/apt_cn_reddelta.yar#L31-L57"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "179265c0b2175bc3d2d581a69e50e9b8b9cc918a6fdc7bcef42fb163c49b077a"
		score = 75
		quality = 85
		tags = "FILE"
		hash1 = "260ebbf392498d00d767a5c5ba695e1a124057c1c01fff2ae76db7853fe4255b"
		hash2 = "9ccb4ed133be5c9c554027347ad8b722f0b4c3f14bfd947edfe75a015bf085e5"
		hash3 = "b3fd750484fca838813e814db7d6491fea36abe889787fb7cf3fb29d9d9f5429"

	strings:
		$x1 = "\\CLRLoader.exe" wide fullword
		$x2 = "/callback.php?token=%s&computername=%s&username=%s" ascii fullword
		$s1 = "DotNetLoader.Program" wide fullword
		$s2 = "/download.php?api=40" ascii fullword
		$s3 = "get %d URLDir" ascii fullword
		$s4 = "Read code failed" ascii fullword
		$s5 = "OpenFile fail!" wide fullword
		$s6 = "Writefile success" wide fullword
		$op1 = { 4c 8d 45 e0 49 8b cc 41 8d 51 c3 e8 34 77 02 00 }

	condition:
		uint16(0)==0x5a4d and filesize <3000KB and 1 of ($x*) or 4 of them
}