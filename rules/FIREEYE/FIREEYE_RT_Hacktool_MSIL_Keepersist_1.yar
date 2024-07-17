rule FIREEYE_RT_Hacktool_MSIL_Keepersist_1 : FILE
{
	meta:
		description = "The TypeLibGUID present in a .NET binary maps directly to the ProjectGuid found in the '.csproj' file of a .NET project. This rule looks for .NET PE files that contain the ProjectGuid found in the 'KeePersist' project."
		author = "FireEye"
		id = "950a4744-2696-5eb7-8524-7f689cb5dbb0"
		date = "2020-12-09"
		modified = "2020-12-09"
		reference = "https://github.com/mandiant/red_team_tool_countermeasures/"
		source_url = "https://github.com/mandiant/red_team_tool_countermeasures//blob/3561b71724dbfa3e2bb78106aaa2d7f8b892c43b/rules/KEEPERSIST/production/yara/HackTool_MSIL_KeePersist_1.yar#L4-L15"
		license_url = "https://github.com/mandiant/red_team_tool_countermeasures//blob/3561b71724dbfa3e2bb78106aaa2d7f8b892c43b/LICENSE.txt"
		hash = "dd8805d0e470e59b829d98397507d8c2"
		logic_hash = "eae67c77a64ca07f9ef59a356bb2c3f3131f14e7f17c898ef8857a21090ace0e"
		score = 75
		quality = 73
		tags = "FILE"
		rev = 2

	strings:
		$typelibguid0 = "1df47db2-7bb8-47c2-9d85-5f8d3f04a884" ascii nocase wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}