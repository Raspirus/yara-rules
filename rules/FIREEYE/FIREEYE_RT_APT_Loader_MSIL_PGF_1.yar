rule FIREEYE_RT_APT_Loader_MSIL_PGF_1 : FILE
{
	meta:
		description = "base.cs"
		author = "FireEye"
		id = "39d9821f-86e8-528a-a0a9-287dbe325484"
		date = "2020-11-24"
		date = "2020-11-24"
		modified = "2020-12-09"
		reference = "https://github.com/mandiant/red_team_tool_countermeasures/"
		source_url = "https://github.com/mandiant/red_team_tool_countermeasures//blob/3561b71724dbfa3e2bb78106aaa2d7f8b892c43b/rules/PGF/production/yara/APT_Loader_MSIL_PGF_1.yar#L4-L17"
		license_url = "https://github.com/mandiant/red_team_tool_countermeasures//blob/3561b71724dbfa3e2bb78106aaa2d7f8b892c43b/LICENSE.txt"
		hash = "a495c6d11ff3f525915345fb762f8047"
		logic_hash = "4174ed53336f3951d26282dc81b99b2044ac6350d4b4c0074194a9b4acecefee"
		score = 75
		quality = 75
		tags = "FILE"
		rev = 1

	strings:
		$sb1 = { 72 [4] 6F [2] 00 0A 26 [0-16] 0? 6F [2] 00 0A [1-3] 0? 28 [2] 00 0A [0-1] 0? 72 [4-5] 0? 28 [2] 00 0A [0-1] 0? 6F [2] 00 0A 13 ?? 1? 13 ?? 38 [8-16] 91 [3-6] 8E 6? 5D 91 61 D2 9C 11 ?? 1? 58 13 [3-5] 8E 6? 3F }

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and all of them
}