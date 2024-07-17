rule JPCERTCC_Wellmess : FILE
{
	meta:
		description = "detect WellMess in memory"
		author = "JPCERT/CC Incident Response Group"
		id = "07084b85-b4fa-5534-aca5-1ddac3a3988b"
		date = "2021-08-16"
		modified = "2021-08-16"
		reference = "internal research"
		source_url = "https://github.com/JPCERTCC/MalConfScan//blob/19ec0d145535a6a4cfd37c0960114f455a8c343e/yara/rule.yara#L550-L569"
		license_url = "https://github.com/JPCERTCC/MalConfScan//blob/19ec0d145535a6a4cfd37c0960114f455a8c343e/LICENSE.txt"
		logic_hash = "1f5a1ba51dd99eadaf5de344539712057f4635b060d4f306b50a6ecb65931970"
		score = 75
		quality = 80
		tags = "FILE"
		rule_usage = "memory scan"
		hash1 = "0322c4c2d511f73ab55bf3f43b1b0f152188d7146cc67ff497ad275d9dd1c20f"
		hash2 = "8749c1495af4fd73ccfc84b32f56f5e78549d81feefb0c1d1c3475a74345f6a8 "

	strings:
		$botlib1 = "botlib.wellMess" ascii
		$botlib2 = "botlib.Command" ascii
		$botlib3 = "botlib.Download" ascii
		$botlib4 = "botlib.AES_Encrypt" ascii
		$dotnet1 = "WellMess" ascii
		$dotnet2 = "<;head;><;title;>" ascii wide
		$dotnet3 = "<;title;><;service;>" ascii wide
		$dotnet4 = "AES_Encrypt" ascii

	condition:
		( uint16(0)==0x5A4D) and ( all of ($botlib*) or all of ($dotnet*))
}