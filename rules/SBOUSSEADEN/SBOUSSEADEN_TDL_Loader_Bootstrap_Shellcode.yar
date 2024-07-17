
rule SBOUSSEADEN_TDL_Loader_Bootstrap_Shellcode : FILE
{
	meta:
		description = "No description has been set in the source file - SBousseaden"
		author = "SBousseaden"
		id = "a2adedef-ba38-599f-b52c-e2156aa5ef98"
		date = "2020-10-10"
		modified = "2020-10-10"
		reference = "https://github.com/hfiref0x/TDL"
		source_url = "https://github.com/sbousseaden/YaraHunts//blob/71b27a2a7c57c2aa1877a11d8933167794e2b4fb/tdl_loader_bootstrat_shellcode.yara#L1-L9"
		license_url = "N/A"
		logic_hash = "14a993b415e330e284503c409ab66445c5e369a21ef0be37297d9c8946b5559b"
		score = 75
		quality = 75
		tags = "FILE"

	strings:
		$shc1 = {41 B8 54 64 6C 53 48 63 6B 3C 48 03 EB 44 8B 7D 50 41 8D 97 00 10 00 00 41 FF D1}
		$shc2 = {41 B8 54 64 6C 53 4C 63 73 3C 4C 03 F3 45 8B 7E 50 41 8D 97 00 10 00 00 41 FF D1 45 33 C9}

	condition:
		uint16(0)==0x5a4d and any of ($shc*)
}