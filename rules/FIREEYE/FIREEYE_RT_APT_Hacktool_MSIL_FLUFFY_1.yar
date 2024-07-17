rule FIREEYE_RT_APT_Hacktool_MSIL_FLUFFY_1 : FILE
{
	meta:
		description = "No description has been set in the source file - FireEye-RT"
		author = "FireEye"
		id = "6593202d-9b30-59ed-98c0-3e730fb5ceb7"
		date = "2020-12-04"
		date = "2020-12-04"
		modified = "2020-12-09"
		reference = "https://github.com/mandiant/red_team_tool_countermeasures/"
		source_url = "https://github.com/mandiant/red_team_tool_countermeasures//blob/3561b71724dbfa3e2bb78106aaa2d7f8b892c43b/rules/FLUFFY/production/yara/APT_HackTool_MSIL_FLUFFY_1.yar#L4-L18"
		license_url = "https://github.com/mandiant/red_team_tool_countermeasures//blob/3561b71724dbfa3e2bb78106aaa2d7f8b892c43b/LICENSE.txt"
		hash = "11b5aceb428c3e8c61ed24a8ca50553e"
		logic_hash = "4d91c96ab7b628e88f79ee193612acc959448fe2220ef54371f5f5c6e7305d86"
		score = 75
		quality = 75
		tags = "FILE"
		rev = 1

	strings:
		$sb1 = { 0E ?? 1? 72 [4] 28 [2] 00 06 [0-16] 28 [2] 00 0A [2-80] 1F 58 0? [0-32] 28 [2] 00 06 [2-32] 1? 28 [2] 00 06 0? 0? 6F [2] 00 06 [2-4] 1F 0B }
		$sb2 = { 73 [2] 00 06 13 ?? 11 ?? 11 ?? 7D [2] 00 04 11 ?? 73 [2] 00 0A 7D [2] 00 04 0E ?? 2D ?? 11 ?? 7B [2] 00 04 72 [4] 28 [2] 00 0A [2-32] 0? 28 [2] 00 0A [2-16] 11 ?? 7B [2] 00 04 0? 28 [2] 00 0A 1? 28 [2] 00 0A [2-32] 7E [2] 00 0A [0-32] FE 15 [2] 00 02 [0-16] 7D [2] 00 04 28 [2] 00 06 [2-32] 7B [2] 00 04 7D [2] 00 04 [2-32] 7C [2] 00 04 FE 15 [2] 00 02 [0-16] 11 ?? 8C [2] 00 02 28 [2] 00 0A 28 [2] 00 0A [2-80] 8C [2] 00 02 28 [2] 00 0A 12 ?? 12 ?? 12 ?? 28 [2] 00 06 }
		$ss1 = "\x00Fluffy\x00"

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and all of them
}