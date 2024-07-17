rule FIREEYE_RT_Loader_Win_Generic_18 : FILE
{
	meta:
		description = "No description has been set in the source file - FireEye-RT"
		author = "FireEye"
		id = "6f44bd64-29bd-50e2-8b61-7ba61bb1f688"
		date = "2020-11-25"
		date = "2020-11-25"
		modified = "2020-12-09"
		reference = "https://github.com/mandiant/red_team_tool_countermeasures/"
		source_url = "https://github.com/mandiant/red_team_tool_countermeasures//blob/3561b71724dbfa3e2bb78106aaa2d7f8b892c43b/rules/BEACON/supplemental/yara/Loader_Win_Generic_18.yar#L4-L19"
		license_url = "https://github.com/mandiant/red_team_tool_countermeasures//blob/3561b71724dbfa3e2bb78106aaa2d7f8b892c43b/LICENSE.txt"
		hash = "c74ebb6c238bbfaefd5b32d2bf7c7fcc"
		logic_hash = "28c9497f646fcf3daf7007d7afd37971dd85382062c064173f13049ad419fef1"
		score = 75
		quality = 75
		tags = "FILE"
		rev = 3

	strings:
		$s0 = { 89 [1-16] FF 15 [4-16] 89 [1-24] E8 [4-16] 89 C6 [4-24] 8D [1-8] 89 [1-4] 89 [1-4] E8 [4-16] 89 [1-8] E8 [4-24] 01 00 00 00 [1-8] 89 [1-8] E8 [4-64] 8A [1-8] 88 }
		$s2 = { 83 EC [4-24] 00 10 00 00 [4-24] C7 44 24 ?? ?? 00 00 00 [0-8] FF 15 [4-24] 89 [1-4] 89 [1-4] 89 [1-8] FF 15 [4-16] 3? ?? 7? [4-24] 20 00 00 00 [4-24] FF 15 [4-32] F3 A5 }
		$si1 = "fread" fullword
		$si2 = "fwrite" fullword

	condition:
		( uint16(0)==0x5A4D) and ( uint32( uint32(0x3C))==0x00004550) and all of them
}