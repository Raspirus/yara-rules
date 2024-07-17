rule FIREEYE_RT_Hacktool_Win64_Andrewspecial_1 : FILE
{
	meta:
		description = "No description has been set in the source file - FireEye-RT"
		author = "FireEye"
		id = "20ce4902-4eb3-5ecf-aa8c-0515965dde57"
		date = "2020-11-25"
		date = "2020-11-25"
		modified = "2020-12-09"
		reference = "https://github.com/mandiant/red_team_tool_countermeasures/"
		source_url = "https://github.com/mandiant/red_team_tool_countermeasures//blob/3561b71724dbfa3e2bb78106aaa2d7f8b892c43b/rules/TITOSPECIAL/production/yara/HackTool_Win64_AndrewSpecial_1.yar#L4-L18"
		license_url = "https://github.com/mandiant/red_team_tool_countermeasures//blob/3561b71724dbfa3e2bb78106aaa2d7f8b892c43b/LICENSE.txt"
		hash = "4456e52f6f8543c3ba76cb25ea3e9bd2"
		logic_hash = "96f06c46dfec795fcfd08c188853d0a3f781003ae118833719a175eb59049c0d"
		score = 75
		quality = 75
		tags = "FILE"
		rev = 5

	strings:
		$dump = { 33 D2 B9 FF FF 1F 00 FF 15 [10-90] 00 00 00 00 [2-6] 80 00 00 00 [2-6] 02 00 00 00 45 33 C9 45 33 C0 BA 00 00 00 10 48 8D 0D [4] FF 15 [4-120] 00 00 00 00 [2-6] 00 00 00 00 [2-6] 00 00 00 00 41 B9 02 00 00 00 [6-15] E8 [4-20] FF 15 }
		$shellcode_x64 = { 4C 8B D1 B8 3C 00 00 00 0F 05 C3 }
		$shellcode_x64_inline = { C6 44 24 ?? 4C C6 44 24 ?? 8B C6 44 24 ?? D1 C6 44 24 ?? B8 C6 44 24 ?? 3C C6 44 24 ?? 00 C6 44 24 ?? 00 C6 44 24 ?? 00 C6 44 24 ?? 0F C6 44 24 ?? 05 C6 44 24 ?? C3 }

	condition:
		( uint16(0)==0x5A4D) and ( uint32( uint32(0x3C))==0x00004550) and ( uint16( uint32(0x3C)+0x18)==0x020B) and $dump and any of ($shellcode*)
}