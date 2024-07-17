rule SIGNATURE_BASE_APT_FIN7_Sample_EXE_Aug18_1 : FILE
{
	meta:
		description = "Detects FIN7 Sample"
		author = "Florian Roth (Nextron Systems)"
		id = "7c66a234-9dee-5279-b855-892b12d036ff"
		date = "2018-08-01"
		modified = "2023-12-05"
		reference = "https://www.fireeye.com/blog/threat-research/2018/08/fin7-pursuing-an-enigmatic-and-evasive-global-criminal-operation.html"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/apt_fin7.yar#L250-L275"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "780e2cb9a704e0df0383737928c2cfc8aa5de5a8f3c9dc67de866d5ac73b8402"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "608003c2165b0954f396d835882479f2504648892d0393f567e4a4aa90659bf9"
		hash2 = "deb62514704852ccd9171d40877c59031f268db917c23d00a2f0113dab79aa3b"
		hash3 = "16de81428a034c7b2636c4a875809ab62c9eefcd326b50c3e629df3b141cc32b"
		hash4 = "3937abdd1fd63587022ed540a31c58c87c2080cdec51dd24af3201a6310059d4"
		hash5 = "7789a3d7d05c30b4efaf3f2f5811804daa56d78a9a660968a4f1f9a78a9108a0"

	strings:
		$s1 = "x0=%d, y0=%d, x1=%d, y1=%d" fullword ascii
		$s2 = "dx=%d, dy=%d" fullword ascii
		$s3 = "Error with JP2H box size" fullword ascii
		$co1 = { 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
               00 00 00 00 00 00 00 00 00 00 00 2E 63 6F 64 65
               00 00 00 }

	condition:
		uint16(0)==0x5a4d and filesize <1000KB and all of ($s*) and $co1 at 0x015D
}