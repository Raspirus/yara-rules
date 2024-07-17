import "pe"


rule FIREEYE_RT_FE_APT_Loader_MSIL_REVOLVER_1 : FILE
{
	meta:
		description = "No description has been set in the source file - FireEye-RT"
		author = "FireEye"
		id = "d99620e0-39ed-58db-acce-0d885a9e0bf7"
		date = "2020-12-18"
		modified = "2020-12-18"
		reference = "https://github.com/mandiant/red_team_tool_countermeasures/"
		source_url = "https://github.com/mandiant/red_team_tool_countermeasures//blob/3561b71724dbfa3e2bb78106aaa2d7f8b892c43b/rules/REVOLVER/production/yara/APT_Loader_MSIL_REVOLVER_1.yar#L5-L14"
		license_url = "https://github.com/mandiant/red_team_tool_countermeasures//blob/3561b71724dbfa3e2bb78106aaa2d7f8b892c43b/LICENSE.txt"
		logic_hash = "1231f4c961dec122ebcb142052c2c7c03acf9b556cdb71a3efabde6bcf50a939"
		score = 75
		quality = 75
		tags = "FILE"

	strings:
		$inject = { 28 [2] 00 06 0? 0? 7B [2] 00 04 7E [2] 00 0A 28 [2] 00 0A [2-40] 7E [2] 00 0A 0? 20 00 10 00 00 28 [2] 00 0A 0? 28 [2] 00 0A 6F [2] 00 0A 1? ?? 7E [2] 00 0A 1? ?? 20 00 30 00 00 1F 40 28 [2] 00 06 [2-40] 28 [2] 00 0A 1? 3? ?? 7E [2] 00 04 7E [2] 00 04 28 [2] 00 0A 28 [2] 00 06 1? ?? 1? ?? 1? 0? 1? ?? 8? 6? 28 [2] 00 0A 2? ?? 7E [2] 00 04 7E [2] 00 04 28 [2] 00 0A 28 [2] 00 06 1? ?? 1? ?? 1? 0? 1? ?? 8? 6? 28 [2] 00 0A 1? ?? FE 15 [2] 00 02 1? ?? 72 [2] 00 70 28 [2] 00 06 1? ?? FE 15 [2] 00 02 1? ?? 1? ?? 1? 28 [2] 00 06 2? 7E [2] 00 0A 1? ?? 0? 7B [2] 00 04 1? ?? 1? 1? ?? 28 [2] 00 06 2? ?? 1? ?? 7E [2] 00 0A 28 [2] 00 0A [2-10] 7E [2] 00 0A 1? ?? 1? ?? 20 [2] 1F 00 7E [2] 00 0A 28 [2] 00 0A 6F [2] 00 0A 1? ?? 7E [2] 00 0A 1? 1? 20 [2] 00 00 20 [2] 00 00 7E [2] 00 0A 28 [2] 00 06 2? 1? ?? 7E [2] 00 0A 28 [2] 00 0A [2-40] 1? ?? 0? 7E [2] 00 0A 7E [2] 00 0A 7E [2] 00 0A 28 [2] 00 06 2? ?? 2? 1? 1? ?? 1? ?? 1? ?? 28 [2] 00 06 }
		$iz1 = /_Cor(Exe|Dll)Main/ fullword

	condition:
		( uint16(0)==0x5A4D) and ( uint32( uint32(0x3C))==0x00004550) and all of them
}