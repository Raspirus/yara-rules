rule FIREEYE_RT_Loader_MSIL_DUEDLLIGENCE_3 : FILE
{
	meta:
		description = "No description has been set in the source file - FireEye-RT"
		author = "FireEye"
		id = "42e4e777-6d51-5733-97df-dc27f13a27b7"
		date = "2020-12-18"
		modified = "2020-12-18"
		reference = "https://github.com/mandiant/red_team_tool_countermeasures/"
		source_url = "https://github.com/mandiant/red_team_tool_countermeasures//blob/3561b71724dbfa3e2bb78106aaa2d7f8b892c43b/rules/DUEDLLIGENCE/production/yara/Loader_MSIL_DUEDLLIGENCE_3.yar#L5-L16"
		license_url = "https://github.com/mandiant/red_team_tool_countermeasures//blob/3561b71724dbfa3e2bb78106aaa2d7f8b892c43b/LICENSE.txt"
		logic_hash = "41cc6a4c7765b1e5e88d12660b69e434c83938ca974b9ccf6545b4dd5dd78378"
		score = 75
		quality = 75
		tags = "FILE"

	strings:
		$create_thread_injected = { 7E [2] 00 0A 0A 16 0B 16 8D [2] 00 01 0C 28 [2] 00 06 2? ?? 2A 28 [2] 00 0A 1E 3? ?? 7E [2] 00 04 7E [2] 00 04 28 [2] 00 0A 28 [2] 00 06 0C 2? ?? 7E [2] 00 04 7E [2] 00 04 28 [2] 00 0A 28 [2] 00 06 0C 7E [2] 00 0A 08 8E 69 7E [2] 00 04 7E [2] 00 04 28 [2] 00 06 0D 09 7E [2] 00 0A 28 [2] 00 0A }
		$iz1 = /_Cor(Exe|Dll)Main/ fullword
		$rc4 = { 20 00 01 00 00 8D [2] 00 01 1? ?? 20 00 01 00 00 8D [2] 00 01 1? ?? 03 8E 69 8D [2] 00 01 1? ?? 16 0B 2B ?? 1? ?? 07 02 07 02 8E 69 5D 91 9E 1? ?? 07 07 9E 07 17 58 0B 07 20 00 01 00 00 32 }
		$suspended_process = { 12 ?? FE 15 [2] 00 02 1? ?? FE 15 [2] 00 02 02 14 7E [2] 00 0A 7E [2] 00 0A 16 20 [2] 00 08 7E [2] 00 0A 14 12 ?? 12 ?? 28 [2] 00 06 }

	condition:
		( uint16(0)==0x5A4D) and ( uint32( uint32(0x3C))==0x00004550) and all of them
}