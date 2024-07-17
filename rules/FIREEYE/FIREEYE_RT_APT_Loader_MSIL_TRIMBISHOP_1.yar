
rule FIREEYE_RT_APT_Loader_MSIL_TRIMBISHOP_1 : FILE
{
	meta:
		description = "No description has been set in the source file - FireEye-RT"
		author = "FireEye"
		id = "1a3f4247-25f4-51ca-b881-209c0753b915"
		date = "2020-12-03"
		date = "2020-12-03"
		modified = "2020-12-09"
		reference = "https://github.com/mandiant/red_team_tool_countermeasures/"
		source_url = "https://github.com/mandiant/red_team_tool_countermeasures//blob/3561b71724dbfa3e2bb78106aaa2d7f8b892c43b/rules/TRIMBISHOP/production/yara/APT_Loader_MSIL_TRIMBISHOP_1.yar#L4-L22"
		license_url = "https://github.com/mandiant/red_team_tool_countermeasures//blob/3561b71724dbfa3e2bb78106aaa2d7f8b892c43b/LICENSE.txt"
		hash = "e91670423930cbbd3dbf5eac1f1a7cb6"
		logic_hash = "f020efff58c8b7761d700c662c422a9e1ffdf8fe5f6648e421b7c257e3b8d078"
		score = 75
		quality = 75
		tags = "FILE"
		rev = 1

	strings:
		$sb1 = { 28 [2] 00 06 0A 06 7B [2] 00 04 [12-64] 06 7B [2] 00 04 6E 28 [2] 00 06 0B 07 7B [2] 00 04 [12-64] 0? 7B [2] 00 04 0? 7B [2] 00 04 0? 7B [2] 00 04 6E 28 [2] 00 06 0? 0? 7B [2] 00 04 [12-80] 0? 7B [2] 00 04 1? 0? 7B [2] 00 04 }
		$sb2 = { 0F ?? 7C [2] 00 04 28 [2] 00 0A 8C [2] 00 01 [20-80] 28 [2] 00 06 0? 0? 7E [2] 00 0A 28 [2] 00 0A [12-80] 7E [2] 00 0A 13 ?? 0? 7B [2] 00 04 28 [2] 00 0A 0? 28 [2] 00 0A 58 28 [2] 00 0A 13 [1-32] 28 [2] 00 0A [0-32] D0 [2] 00 02 28 [2] 00 0A 28 [2] 00 0A 74 [2] 00 02 }
		$ss1 = "\x00NtMapViewOfSection\x00"
		$ss2 = "\x00NtOpenProcess\x00"
		$ss3 = "\x00NtAlertResumeThread\x00"
		$ss4 = "\x00LdrGetProcedureAddress\x00"
		$tb1 = "\x00DTrim.Execution.DynamicInvoke\x00"

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and (@sb1[1]<@sb2[1]) and ( all of ($ss*)) and ( all of ($tb*))
}