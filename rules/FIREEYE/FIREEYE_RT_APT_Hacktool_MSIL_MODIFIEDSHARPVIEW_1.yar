
rule FIREEYE_RT_APT_Hacktool_MSIL_MODIFIEDSHARPVIEW_1 : FILE
{
	meta:
		description = "The TypeLibGUID present in a .NET binary maps directly to the ProjectGuid found in the '.csproj' file of a .NET project. This rule looks for .NET PE files that contain the ProjectGuid found in the 'modifiedsharpview' project."
		author = "FireEye"
		id = "e07d3d4b-fba3-5df7-85f4-927bb8cec2d1"
		date = "2020-12-09"
		modified = "2020-12-09"
		reference = "https://github.com/mandiant/red_team_tool_countermeasures/"
		source_url = "https://github.com/mandiant/red_team_tool_countermeasures//blob/3561b71724dbfa3e2bb78106aaa2d7f8b892c43b/rules/UNCATEGORIZED/production/yara/APT_HackTool_MSIL_MODIFIEDSHARPVIEW_1.yar#L4-L15"
		license_url = "https://github.com/mandiant/red_team_tool_countermeasures//blob/3561b71724dbfa3e2bb78106aaa2d7f8b892c43b/LICENSE.txt"
		hash = "db0eaad52465d5a2b86fdd6a6aa869a5"
		logic_hash = "a47c48da998243fab92665649fb9d6ecc6ac32e1fd884c2c0d5ccecb05290c10"
		score = 75
		quality = 73
		tags = "FILE"
		rev = 3

	strings:
		$typelibguid0 = "22a156ea-2623-45c7-8e50-e864d9fc44d3" ascii nocase wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}