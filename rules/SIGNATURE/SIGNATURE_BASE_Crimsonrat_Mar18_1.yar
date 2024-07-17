rule SIGNATURE_BASE_Crimsonrat_Mar18_1 : FILE
{
	meta:
		description = "Detects CrimsonRAT malware"
		author = "Florian Roth (Nextron Systems)"
		id = "af21876c-f99d-5307-abba-02c57ee93df0"
		date = "2018-03-06"
		modified = "2023-12-05"
		reference = "Internal Research"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/gen_crimson_rat.yar#L11-L42"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "59b01a98a70c4bac08d396418fac24eb96e461a45502f63edc2a9aa87e05f960"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "acf2e8013b6fafcf436d5a05049896504ffa2e982bca05155d19981d1931c611"
		hash2 = "7ca6e5ef1d346ec35993c910128a3526b098a07445131784a9358bf5679e3975"
		hash3 = "be4264973de9886caedae1cb707586588d0da85ac7a2ad277db4258033ea12a8"
		hash4 = "acf2e8013b6fafcf436d5a05049896504ffa2e982bca05155d19981d1931c611"
		hash5 = "ff52b4a64ed7caeab00350e493968dbdb159aeb545fcba67d83ab9b158464de4"

	strings:
		$x1 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run|" wide
		$x2 = "\\Release\\RTLBot.pdb" ascii
		$x3 = "cmd.exe/c systeminfo >> 1.txt" fullword wide
		$x4 = "/online >> Get online target with important info" fullword wide
		$x5 = "/screen >> ScreenShot from target PC" fullword wide
		$x6 = "/restart >> Restart Target PC" fullword wide
		$x7 = "/log_key >> Get log key file" fullword wide
		$a1 = "get_ShiftKey" fullword ascii
		$a2 = "get_ControlKey" fullword ascii
		$a3 = "get_AltKey" fullword ascii
		$a4 = "get_MineInterval" fullword ascii
		$fp1 = "Copyright Software Secure" wide

	condition:
		uint16(0)==0x5a4d and filesize <400KB and (1 of ($x*) or all of ($a*)) and not 1 of ($fp*)
}