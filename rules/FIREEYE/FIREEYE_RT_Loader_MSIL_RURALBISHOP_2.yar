
rule FIREEYE_RT_Loader_MSIL_RURALBISHOP_2 : FILE
{
	meta:
		description = "No description has been set in the source file - FireEye-RT"
		author = "FireEye"
		id = "3befb3f2-81d1-5db2-84d9-773158b9837c"
		date = "2020-12-03"
		date = "2020-12-03"
		modified = "2020-12-09"
		reference = "https://github.com/mandiant/red_team_tool_countermeasures/"
		source_url = "https://github.com/mandiant/red_team_tool_countermeasures//blob/3561b71724dbfa3e2bb78106aaa2d7f8b892c43b/rules/TRIMBISHOP/new/yara/Loader_MSIL_RURALBISHOP_2.yar#L4-L22"
		license_url = "https://github.com/mandiant/red_team_tool_countermeasures//blob/3561b71724dbfa3e2bb78106aaa2d7f8b892c43b/LICENSE.txt"
		hash = "e91670423930cbbd3dbf5eac1f1a7cb6"
		logic_hash = "0467532d643cf0200c6561b0724c884230892bf59db163c311b7d4f8acbb63d6"
		score = 75
		quality = 75
		tags = "FILE"
		rev = 1

	strings:
		$ss1 = "\x00NtMapViewOfSection\x00"
		$ss2 = "\x00NtOpenProcess\x00"
		$ss3 = "\x00NtAlertResumeThread\x00"
		$ss4 = "\x00LdrGetProcedureAddress\x00"
		$ss5 = "\x2f(\x00?\x00i\x00)\x00(\x00-\x00|\x00-\x00-\x00|\x00/\x00)\x00(\x00i\x00|\x00I\x00n\x00j\x00e\x00c\x00t\x00)\x00$\x00"
		$ss6 = "\x2d(\x00?\x00i\x00)\x00(\x00-\x00|\x00-\x00-\x00|\x00/\x00)\x00(\x00c\x00|\x00C\x00l\x00e\x00a\x00n\x00)\x00$\x00"
		$tb1 = "\x00SharpSploit.Execution.DynamicInvoke\x00"

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and all of them
}