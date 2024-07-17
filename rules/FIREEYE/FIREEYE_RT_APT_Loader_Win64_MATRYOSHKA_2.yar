rule FIREEYE_RT_APT_Loader_Win64_MATRYOSHKA_2 : FILE
{
	meta:
		description = "matryoshka.rs"
		author = "FireEye"
		id = "25f916bc-6ee1-5175-903c-4266b0a086e1"
		date = "2020-12-02"
		date = "2020-12-02"
		modified = "2020-12-09"
		reference = "https://github.com/mandiant/red_team_tool_countermeasures/"
		source_url = "https://github.com/mandiant/red_team_tool_countermeasures//blob/3561b71724dbfa3e2bb78106aaa2d7f8b892c43b/rules/MATRYOSHKA/production/yara/APT_Loader_Win64_MATRYOSHKA_2.yar#L4-L20"
		license_url = "https://github.com/mandiant/red_team_tool_countermeasures//blob/3561b71724dbfa3e2bb78106aaa2d7f8b892c43b/LICENSE.txt"
		hash = "7f8102b789303b7861a03290c79feba0"
		logic_hash = "daa6f6d526bf959c268b2c5a4cae33307cfec5e9ca51283131bbfa66a582b505"
		score = 75
		quality = 75
		tags = "FILE"
		rev = 1

	strings:
		$sb1 = { 4D [2] 00 49 [2] 08 B? 02 00 00 00 31 ?? E8 [4] 48 89 ?? 48 89 ?? 4C 89 ?? 49 89 ?? E8 [4] 4C 89 ?? 48 89 ?? E8 [4] 83 [2] 01 0F 84 [4] 48 89 ?? 48 8B [2] 48 8B [2] 48 89 [5] 48 89 [5] 48 89 [5] 41 B? [4] 4C 89 ?? 31 ?? E8 [4] C7 45 [5] 48 89 ?? 4C 89 ?? E8 [4] 85 C0 }
		$sb2 = { 4C [2] 0F 83 [4] 41 0F [3] 01 41 32 [2] 00 48 8B [5] 48 3B [5] 75 ?? 41 B? 01 00 00 00 4C 89 ?? E8 [4] E9 }
		$si1 = "CreateToolhelp32Snapshot" fullword
		$si2 = "Process32Next" fullword

	condition:
		( uint16(0)==0x5A4D) and ( uint32( uint32(0x3C))==0x00004550) and ( uint16( uint32(0x3C)+0x18)==0x020B) and all of them
}