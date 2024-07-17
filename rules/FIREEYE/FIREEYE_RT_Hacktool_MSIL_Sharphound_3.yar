
rule FIREEYE_RT_Hacktool_MSIL_Sharphound_3 : FILE
{
	meta:
		description = "The TypeLibGUID present in a .NET binary maps directly to the ProjectGuid found in the '.csproj' file of a .NET project. This rule looks for .NET PE files that contain the ProjectGuid found in the public SharpHound3 project."
		author = "FireEye"
		id = "456b3208-1e8d-5eb7-81ee-39f1c886c5a7"
		date = "2020-12-09"
		modified = "2020-12-09"
		reference = "https://github.com/mandiant/red_team_tool_countermeasures/"
		source_url = "https://github.com/mandiant/red_team_tool_countermeasures//blob/3561b71724dbfa3e2bb78106aaa2d7f8b892c43b/rules/PUPPYHOUND/production/yara/HackTool_MSIL_SharpHound_3.yar#L4-L15"
		license_url = "https://github.com/mandiant/red_team_tool_countermeasures//blob/3561b71724dbfa3e2bb78106aaa2d7f8b892c43b/LICENSE.txt"
		hash = "eeedc09570324767a3de8205f66a5295"
		logic_hash = "baeea6cae42c755ee389378229b2b206c82f60f75a5ce5f9cfa06871fc9507d1"
		score = 75
		quality = 73
		tags = "FILE"
		rev = 4

	strings:
		$typelibguid1 = "A517A8DE-5834-411D-ABDA-2D0E1766539C" ascii nocase wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and $typelibguid1
}