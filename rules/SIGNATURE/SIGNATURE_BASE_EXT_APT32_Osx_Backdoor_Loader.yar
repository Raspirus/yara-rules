rule SIGNATURE_BASE_EXT_APT32_Osx_Backdoor_Loader : FILE
{
	meta:
		description = "Detects APT32 backdoor loader on OSX"
		author = "Facebook"
		id = "ac313bd8-bf15-5b72-b651-35015f71dd90"
		date = "2023-12-05"
		modified = "2023-12-05"
		reference = "https://about.fb.com/news/2020/12/taking-action-against-hackers-in-bangladesh-and-vietnam/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/apt_apt32.yar#L22-L49"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		hash = "768510fa9eb807bba9c3dcb3c7f87b771e20fa3d81247539e9ea4349205e39eb"
		logic_hash = "26964f95a9298b838e06fb9d7f739c8b87a976d8da7fb08416e952d26e84b84e"
		score = 75
		quality = 85
		tags = "FILE"

	strings:
		$a1 = { 00 D2 44 8A 04 0F 44 88 C0 C0 E8 07 08 D0 88 44 0F FF 48 FF C1 48 83 F9 10 44 88 C2 }
		$a2 = { 41 0F 10 04 07 0F 57 84 05 A0 FE FF FF 41 0F 11 04 07 48 83 C0 10 48 83 F8 10 75 }
		$e1 = { CA CF 3E F2 DA 43 E6 D1  D5 6C D4 23 3A AE F1 B2 }
		$e2 = "MlkHVdRbOkra9s+G65MAoLga340t3+zj/u8LPfP3hig="
		$e3 = { 5A 69 98 0E 6C 4B 5C 69  7E 19 34 3B C3 07 CA 13 }
		$e4 = "1Sib4HfPuRQjpxIpECnxxTPiu3FXOFAHMx/+9MEVv9M+h1ngV7T5WUP3b0zsg0Qd"
		$e5 = "_ArchaeologistCodeine"
		$e6 = "_PlayerAberadurtheIncomprehensible"

	condition:
		(( uint32(0)==0xfeedface or uint32be(0)==0xfeedface) or ( uint32(0)==0xfeedfacf or uint32be(0)==0xfeedfacf)) and (2 of ($e*) or all of ($a*))
}