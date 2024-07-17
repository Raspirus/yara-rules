rule FIREEYE_RT_APT_Loader_MSIL_WILDCHILD_1 : FILE
{
	meta:
		description = "No description has been set in the source file - FireEye-RT"
		author = "FireEye"
		id = "b9e0707e-98eb-55da-ad1d-6a84bd113747"
		date = "2020-12-01"
		date = "2020-12-01"
		modified = "2020-12-09"
		reference = "https://github.com/mandiant/red_team_tool_countermeasures/"
		source_url = "https://github.com/mandiant/red_team_tool_countermeasures//blob/3561b71724dbfa3e2bb78106aaa2d7f8b892c43b/rules/WILDCHILD/production/yara/APT_Loader_MSIL_WILDCHILD_1.yar#L4-L18"
		license_url = "https://github.com/mandiant/red_team_tool_countermeasures//blob/3561b71724dbfa3e2bb78106aaa2d7f8b892c43b/LICENSE.txt"
		hash = "6f04a93753ae3ae043203437832363c4"
		logic_hash = "a600c3d127f77dc1f99160e4a242e005970de0abd1798296b6a351b968ca1350"
		score = 75
		quality = 75
		tags = "FILE"
		rev = 1

	strings:
		$s1 = "\x00QueueUserAPC\x00"
		$s2 = "\x00WriteProcessMemory\x00"
		$sb1 = { 6F [2] 00 0A 28 [2] 00 0A 6F [2] 00 0A 13 ?? 28 [2] 00 0A 28 [2] 00 0A 13 ?? 11 ?? 11 ?? 28 [2] 00 0A [0-16] 7B [2] 00 04 1? 20 [4] 28 [2] 00 0A 11 ?? 28 [2] 00 0A 28 [2] 00 0A 7E [2] 00 0A 7E [2] 00 0A 28 [2] 00 06 [0-16] 14 7E [2] 00 0A 7E [2] 00 0A 1? 20 04 00 08 08 7E [2] 00 0A 14 12 ?? 12 ?? 28 [2] 00 06 [0-16] 7B [2] 00 04 7E [2] 00 0A [0-16] 8E ?? 7E [2] 00 04 7E [2] 00 04 28 [2] 00 06 [4-120] 28 [2] 00 06 [0-80] 6F [2] 00 0A 6F [2] 00 0A 28 [2] 00 06 13 ?? 11 ?? 11 ?? 7E [2] 00 0A 28 [2] 00 06 }

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and all of them
}