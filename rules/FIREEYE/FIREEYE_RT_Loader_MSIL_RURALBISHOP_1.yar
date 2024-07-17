
rule FIREEYE_RT_Loader_MSIL_RURALBISHOP_1 : FILE
{
	meta:
		description = "No description has been set in the source file - FireEye-RT"
		author = "FireEye"
		id = "1b5f1f39-9fa2-5940-8da3-03808e4b7a5d"
		date = "2020-12-03"
		date = "2020-12-03"
		modified = "2020-12-09"
		reference = "https://github.com/mandiant/red_team_tool_countermeasures/"
		source_url = "https://github.com/mandiant/red_team_tool_countermeasures//blob/3561b71724dbfa3e2bb78106aaa2d7f8b892c43b/rules/TRIMBISHOP/new/yara/Loader_MSIL_RURALBISHOP_1.yar#L4-L22"
		license_url = "https://github.com/mandiant/red_team_tool_countermeasures//blob/3561b71724dbfa3e2bb78106aaa2d7f8b892c43b/LICENSE.txt"
		hash = "e91670423930cbbd3dbf5eac1f1a7cb6"
		logic_hash = "f2244c6761639c1162a77a5e82296903c3cc21fbf46d262c779c5e4d6a2ef937"
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
		$tb1 = "\x00SharpSploit.Execution.DynamicInvoke\x00"

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and (@sb1[1]<@sb2[1]) and ( all of ($ss*)) and ( all of ($tb*))
}