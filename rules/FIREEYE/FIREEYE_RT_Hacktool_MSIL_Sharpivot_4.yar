
rule FIREEYE_RT_Hacktool_MSIL_Sharpivot_4 : FILE
{
	meta:
		description = "The TypeLibGUID present in a .NET binary maps directly to the ProjectGuid found in the '.csproj' file of a .NET project. This rule looks for .NET PE files that contain the ProjectGuid found in the SharPivot project."
		author = "FireEye"
		id = "c1bd64da-6a54-5bc6-8a89-9c8a93dd965c"
		date = "2020-12-09"
		modified = "2020-12-09"
		reference = "https://github.com/mandiant/red_team_tool_countermeasures/"
		source_url = "https://github.com/mandiant/red_team_tool_countermeasures//blob/3561b71724dbfa3e2bb78106aaa2d7f8b892c43b/rules/SHARPIVOT/production/yara/HackTool_MSIL_SharPivot_4.yar#L4-L15"
		license_url = "https://github.com/mandiant/red_team_tool_countermeasures//blob/3561b71724dbfa3e2bb78106aaa2d7f8b892c43b/LICENSE.txt"
		hash = "e4efa759d425e2f26fbc29943a30f5bd"
		logic_hash = "7ef883148926d5786861e5e81b1e645aa2e3ca06bd663f2b5f32e04b5852a218"
		score = 75
		quality = 73
		tags = "FILE"
		rev = 3

	strings:
		$typelibguid1 = "44B83A69-349F-4A3E-8328-A45132A70D62" ascii nocase wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and $typelibguid1
}