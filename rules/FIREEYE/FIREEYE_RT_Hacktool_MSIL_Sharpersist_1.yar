rule FIREEYE_RT_Hacktool_MSIL_Sharpersist_1 : FILE
{
	meta:
		description = "The TypeLibGUID present in a .NET binary maps directly to the ProjectGuid found in the '.csproj' file of a .NET project. This rule looks for .NET PE files that contain the ProjectGuid found in the SharPersist project."
		author = "FireEye"
		id = "586e6c91-6970-57d1-8d8c-05ae9eb6117a"
		date = "2020-12-09"
		modified = "2020-12-09"
		reference = "https://github.com/mandiant/red_team_tool_countermeasures/"
		source_url = "https://github.com/mandiant/red_team_tool_countermeasures//blob/3561b71724dbfa3e2bb78106aaa2d7f8b892c43b/rules/SHARPERSIST/production/yara/HackTool_MSIL_SharPersist_1.yar#L4-L15"
		license_url = "https://github.com/mandiant/red_team_tool_countermeasures//blob/3561b71724dbfa3e2bb78106aaa2d7f8b892c43b/LICENSE.txt"
		hash = "98ecf58d48a3eae43899b45cec0fc6b7"
		logic_hash = "cf480026c31b522850e25ba2d7986773d9c664242a2667ecd33151621c98c91e"
		score = 75
		quality = 73
		tags = "FILE"
		rev = 1

	strings:
		$typelibguid1 = "9D1B853E-58F1-4BA5-AEFC-5C221CA30E48" ascii nocase wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and $typelibguid1
}