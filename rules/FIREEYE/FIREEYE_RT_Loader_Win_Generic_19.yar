rule FIREEYE_RT_Loader_Win_Generic_19 : FILE
{
	meta:
		description = "No description has been set in the source file - FireEye-RT"
		author = "FireEye"
		id = "4f4427ee-0f7d-5442-98a6-402d8b797289"
		date = "2020-12-02"
		date = "2020-12-02"
		modified = "2020-12-09"
		reference = "https://github.com/mandiant/red_team_tool_countermeasures/"
		source_url = "https://github.com/mandiant/red_team_tool_countermeasures//blob/3561b71724dbfa3e2bb78106aaa2d7f8b892c43b/rules/UNCATEGORIZED/supplemental/yara/Loader_Win_Generic_19.yar#L4-L19"
		license_url = "https://github.com/mandiant/red_team_tool_countermeasures//blob/3561b71724dbfa3e2bb78106aaa2d7f8b892c43b/LICENSE.txt"
		hash = "3fb9341fb11eca439b50121c6f7c59c7"
		logic_hash = "6db9696663c19857c1f89339b8cc9b0565e877f34e8d8cf77b89ef22b3f41683"
		score = 75
		quality = 75
		tags = "FILE"
		rev = 1

	strings:
		$s0 = { 8B [1-16] 89 [1-16] E8 [4-32] F3 A4 [0-16] 89 [1-8] E8 }
		$s1 = { 83 EC [1-16] 04 00 00 00 [1-24] 00 30 00 00 [1-24] FF 15 [4-16] EB [16-64] 20 00 00 00 [0-8] FF 15 [4-32] C7 44 24 ?? 00 00 00 00 [0-8] C7 44 24 ?? 00 00 00 00 [0-16] FF 15 }
		$si1 = "VirtualProtect" fullword
		$si2 = "malloc" fullword

	condition:
		( uint16(0)==0x5A4D) and ( uint32( uint32(0x3C))==0x00004550) and all of them
}