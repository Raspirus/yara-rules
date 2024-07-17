rule COD3NYM_Confuserex_Packer : SUSPICIOUS OBFUSCATION FILE
{
	meta:
		description = "ConfuserEx Packer"
		author = "Jonathan Peters"
		id = "cd53a62f-62e3-58a1-8bc3-7f40949e3f00"
		date = "2024-01-09"
		modified = "2024-01-10"
		reference = "https://github.com/cod3nym/detection-rules/"
		source_url = "https://github.com/cod3nym/detection-rules//blob/ad485bff0ce30afb56e367b7f2b76fea81e78fc9/malcat/obfuscators.yar#L79-L99"
		license_url = "https://github.com/cod3nym/detection-rules//blob/ad485bff0ce30afb56e367b7f2b76fea81e78fc9/LICENSE.md"
		logic_hash = "43aee4c01b47ca04ee516d418939ec3e90fd08566f2a4b501c4698b7f9e0225d"
		score = 65
		quality = 80
		tags = "SUSPICIOUS, OBFUSCATION, FILE"
		name = "ConfuserEx"
		category = "obfuscation"
		reliability = 90

	strings:
		$s1 = "GCHandle" ascii
		$s2 = "GCHandleType" ascii
		$op1 = { 5A 20 89 C0 3F 14 6A 5E [8-20] 5A 20 FB 56 4D 44 6A 5E 6D 9E }
		$op2 = { 20 61 FF 6F 00 13 ?? 06 13 ?? 16 13 [10-20] 20 1F 3F 5E 00 5A }
		$op3 = { 16 91 7E [3] 04 17 91 1E 62 60 7E [3] 04 18 91 1F 10 62 60 7E [3] 04 19 91 1F 18 62 }

	condition:
		uint16(0)==0x5a4d and all of ($s*) and 2 of ($op*)
}