rule FIREEYE_RT_APT_Loader_Win32_REDFLARE_2 : FILE
{
	meta:
		description = "No description has been set in the source file - FireEye-RT"
		author = "FireEye"
		id = "6a585401-bfd3-5aad-b484-09b6a30d9af5"
		date = "2020-11-27"
		date = "2020-11-27"
		modified = "2020-12-09"
		reference = "https://github.com/mandiant/red_team_tool_countermeasures/"
		source_url = "https://github.com/mandiant/red_team_tool_countermeasures//blob/3561b71724dbfa3e2bb78106aaa2d7f8b892c43b/rules/REDFLARE/production/yara/APT_Loader_Win32_REDFLARE_2.yar#L4-L17"
		license_url = "https://github.com/mandiant/red_team_tool_countermeasures//blob/3561b71724dbfa3e2bb78106aaa2d7f8b892c43b/LICENSE.txt"
		hash = "4e7e90c7147ee8aa01275894734f4492"
		logic_hash = "98dfb71adbde4f8965e612c19f0965d8fa95805825569290fdf72eb1d86cfb70"
		score = 75
		quality = 75
		tags = "FILE"
		rev = 1

	strings:
		$inject = { 83 F8 01 [4-50] 6A 00 6A 00 68 04 00 00 08 6A 00 6A 00 6A 00 6A 00 5? [10-70] FF 15 [4] 85 C0 [1-20] 6A 04 68 00 10 00 00 5? 6A 00 5? [1-10] FF 15 [4-8] 85 C0 [1-20] 5? 5? 5? 8B [1-4] 5? 5? FF 15 [4] 85 C0 [1-20] 6A 20 [4-20] FF 15 [4] 85 C0 [1-40] 01 00 01 00 [2-20] FF 15 [4] 85 C0 [1-30] FF 15 [4] 85 C0 [1-20] FF 15 [4] 83 F8 FF }
		$s1 = "ResumeThread"

	condition:
		( uint16(0)==0x5A4D) and ( uint32( uint32(0x3C))==0x00004550) and ( uint16( uint32(0x3C)+0x18)==0x010B) and all of them
}