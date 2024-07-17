
rule FIREEYE_RT_APT_Loader_Win64_MATRYOSHKA_1 : FILE
{
	meta:
		description = "matryoshka_process_hollow.rs"
		author = "FireEye"
		id = "69919a80-8ed1-5b8c-911a-ceb75570f11f"
		date = "2020-12-02"
		date = "2020-12-02"
		modified = "2020-12-09"
		reference = "https://github.com/mandiant/red_team_tool_countermeasures/"
		source_url = "https://github.com/mandiant/red_team_tool_countermeasures//blob/3561b71724dbfa3e2bb78106aaa2d7f8b892c43b/rules/MATRYOSHKA/production/yara/APT_Loader_Win64_MATRYOSHKA_1.yar#L4-L19"
		license_url = "https://github.com/mandiant/red_team_tool_countermeasures//blob/3561b71724dbfa3e2bb78106aaa2d7f8b892c43b/LICENSE.txt"
		hash = "44887551a47ae272d7873a354d24042d"
		logic_hash = "46e5480dc95ce8b9d8385c2e44a50b21629301535b93833c13cc3db319ac15dd"
		score = 75
		quality = 75
		tags = "FILE"
		rev = 1

	strings:
		$sb1 = { 48 8B 45 ?? 48 89 85 [0-64] C7 45 ?? 00 00 00 00 31 ?? E8 [4-64] BA 00 10 00 00 [0-32] 41 B8 04 00 00 00 E8 [4] 83 F8 01 [2-32] BA [4] E8 }
		$sb2 = { E8 [4] 83 F8 01 [2-64] 41 B9 00 10 00 00 [0-32] E8 [4] 83 F8 01 [2-32] 3D 4D 5A 00 00 [0-32] 48 63 ?? 3C [0-32] 50 45 00 00 [4-64] 0F B7 [2] 18 81 ?? 0B 01 00 00 [2-32] 81 ?? 0B 02 00 00 [2-32] 8B [2] 28 }
		$sb3 = { 66 C7 45 ?? 48 B8 48 C7 45 ?? 00 00 00 00 66 C7 45 ?? FF E0 [0-64] 41 B9 40 00 00 00 [0-32] E8 [4] 83 F8 01 }

	condition:
		( uint16(0)==0x5A4D) and ( uint32( uint32(0x3C))==0x00004550) and ( uint16( uint32(0x3C)+0x18)==0x020B) and all of them
}