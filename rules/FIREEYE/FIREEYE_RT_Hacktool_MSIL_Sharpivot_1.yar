
rule FIREEYE_RT_Hacktool_MSIL_Sharpivot_1 : FILE
{
	meta:
		description = "No description has been set in the source file - FireEye-RT"
		author = "FireEye"
		id = "c2834bd6-efb0-5dac-adcd-a9450090fc28"
		date = "2020-11-25"
		date = "2020-11-25"
		modified = "2020-12-09"
		reference = "https://github.com/mandiant/red_team_tool_countermeasures/"
		source_url = "https://github.com/mandiant/red_team_tool_countermeasures//blob/3561b71724dbfa3e2bb78106aaa2d7f8b892c43b/rules/SHARPIVOT/production/yara/HackTool_MSIL_SharPivot_1.yar#L4-L18"
		license_url = "https://github.com/mandiant/red_team_tool_countermeasures//blob/3561b71724dbfa3e2bb78106aaa2d7f8b892c43b/LICENSE.txt"
		hash = "e4efa759d425e2f26fbc29943a30f5bd"
		logic_hash = "1c71b9641e30c9764f3503e49f8f85472d7e62384c8dd2b420c4fa2b2fccda4f"
		score = 75
		quality = 75
		tags = "FILE"
		rev = 3

	strings:
		$s2 = { 73 ?? 00 00 0A 0A 06 1F ?? 1F ?? 6F ?? 00 00 0A 0B 73 ?? 00 00 0A 0C 16 13 04 2B 5E 23 [8] 06 6F ?? 00 00 0A 5A 23 [8] 58 28 ?? 00 00 0A 28 ?? 00 00 0A 28 ?? 00 00 0A }
		$s3 = "cmd_rpc" wide
		$s4 = "costura"

	condition:
		( uint16(0)==0x5A4D) and ( uint32( uint32(0x3C))==0x00004550) and all of them
}