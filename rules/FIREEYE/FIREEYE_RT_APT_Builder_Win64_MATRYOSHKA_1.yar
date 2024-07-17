
rule FIREEYE_RT_APT_Builder_Win64_MATRYOSHKA_1 : FILE
{
	meta:
		description = "matryoshka_pe_to_shellcode.rs"
		author = "FireEye"
		id = "0afcf13e-5cd3-5c1c-897e-b6d0c283ab0f"
		date = "2020-12-02"
		date = "2020-12-02"
		modified = "2020-12-09"
		reference = "https://github.com/mandiant/red_team_tool_countermeasures/"
		source_url = "https://github.com/mandiant/red_team_tool_countermeasures//blob/3561b71724dbfa3e2bb78106aaa2d7f8b892c43b/rules/MATRYOSHKA/production/yara/APT_Builder_Win64_MATRYOSHKA_1.yar#L4-L20"
		license_url = "https://github.com/mandiant/red_team_tool_countermeasures//blob/3561b71724dbfa3e2bb78106aaa2d7f8b892c43b/LICENSE.txt"
		hash = "8d949c34def898f0f32544e43117c057"
		logic_hash = "b370d7dea44bccc92fc8dbd4ea0ee9bec523820108bf8bc67acb17ebf9835f74"
		score = 75
		quality = 75
		tags = "FILE"
		rev = 1

	strings:
		$sb1 = { 4D 5A 45 52 [0-32] E8 [0-32] 00 00 00 00 [0-32] 5B 48 83 EB 09 53 48 81 [0-32] C3 [0-32] FF D3 [0-32] C3 }
		$ss1 = "\x00Stub Size: "
		$ss2 = "\x00Executable Size: "
		$ss3 = "\x00[+] Writing out to file"

	condition:
		( uint16(0)==0x5A4D) and ( uint32( uint32(0x3C))==0x00004550) and ( uint16( uint32(0x3C)+0x18)==0x020B) and all of them
}