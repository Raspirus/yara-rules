rule FIREEYE_RT_Hacktool_MSIL_Wmisharp_1 : FILE
{
	meta:
		description = "The TypeLibGUID present in a .NET binary maps directly to the ProjectGuid found in the '.csproj' file of a .NET project. This rule looks for .NET PE files that contain the ProjectGuid found in the 'WMISharp' project."
		author = "FireEye"
		id = "97b9d057-30d3-5af7-bac6-4dd53f47650f"
		date = "2020-12-09"
		modified = "2020-12-09"
		reference = "https://github.com/mandiant/red_team_tool_countermeasures/"
		source_url = "https://github.com/mandiant/red_team_tool_countermeasures//blob/3561b71724dbfa3e2bb78106aaa2d7f8b892c43b/rules/WMISHARP/production/yara/HackTool_MSIL_WMISharp_1.yar#L4-L15"
		license_url = "https://github.com/mandiant/red_team_tool_countermeasures//blob/3561b71724dbfa3e2bb78106aaa2d7f8b892c43b/LICENSE.txt"
		hash = "dd8805d0e470e59b829d98397507d8c2"
		logic_hash = "d119d52c1410291d582696d5c4c1de3db9008db963c76a9e344959d869c3acc0"
		score = 75
		quality = 73
		tags = "FILE"
		rev = 1

	strings:
		$typelibguid0 = "3a2421d9-c1aa-4fff-ad76-7fcb48ed4bff" ascii nocase wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}