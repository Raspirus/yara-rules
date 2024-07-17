rule FIREEYE_RT_APT_Loader_Win32_PGF_4 : FILE
{
	meta:
		description = "No description has been set in the source file - FireEye-RT"
		author = "FireEye"
		id = "d46d9ae9-cb7d-5a25-9ee2-766097c14af6"
		date = "2020-11-26"
		date = "2020-11-26"
		modified = "2020-12-09"
		reference = "https://github.com/mandiant/red_team_tool_countermeasures/"
		source_url = "https://github.com/mandiant/red_team_tool_countermeasures//blob/3561b71724dbfa3e2bb78106aaa2d7f8b892c43b/rules/PGF/production/yara/APT_Loader_Win32_PGF_4.yar#L4-L17"
		license_url = "https://github.com/mandiant/red_team_tool_countermeasures//blob/3561b71724dbfa3e2bb78106aaa2d7f8b892c43b/LICENSE.txt"
		hash = "4414953fa397a41156f6fa4f9462d207"
		logic_hash = "4256bfd3713f330d76cad9d1ddbba91e588dbca2e2b6842e9482525805ddc1e8"
		score = 75
		quality = 75
		tags = "FILE"
		rev = 1

	strings:
		$sb1 = { C7 44 24 0C 04 00 00 00 C7 44 24 08 00 10 00 00 [4-32] C7 04 24 00 00 00 00 [0-32] FF [1-16] 89 45 ?? 83 7D ?? 00 [2-150] 0F B? ?? 8B [2] B? CD CC CC CC 89 ?? F7 ?? C1 ?? 04 89 ?? C1 ?? 02 [0-32] 0F B? [5-32] 3? [1-16] 88 }
		$sb2 = { C? 45 ?? B8 [0-4] C? 45 ?? 00 [0-64] FF [0-32] E0 [0-32] C7 44 24 08 40 00 00 00 [0-32] C7 44 24 04 07 00 00 00 [0-32] FF [1-64] 89 ?? 0F B? [2-3] 89 ?? 04 0F B? [2] 88 ?? 06 8B ?? 08 8D ?? 01 8B 45 0C }

	condition:
		( uint16(0)==0x5A4D) and ( uint32( uint32(0x3C))==0x00004550) and ( uint16( uint32(0x3C)+0x18)==0x010B) and all of them
}