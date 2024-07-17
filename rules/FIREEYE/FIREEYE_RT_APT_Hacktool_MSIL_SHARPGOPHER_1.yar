rule FIREEYE_RT_APT_Hacktool_MSIL_SHARPGOPHER_1 : FILE
{
	meta:
		description = "The TypeLibGUID present in a .NET binary maps directly to the ProjectGuid found in the '.csproj' file of a .NET project. This rule looks for .NET PE files that contain the ProjectGuid found in the 'sharpgopher' project."
		author = "FireEye"
		id = "cc8eb9cd-9a51-5fab-b0a4-247baaa69dd7"
		date = "2020-12-09"
		modified = "2020-12-09"
		reference = "https://github.com/mandiant/red_team_tool_countermeasures/"
		source_url = "https://github.com/mandiant/red_team_tool_countermeasures//blob/3561b71724dbfa3e2bb78106aaa2d7f8b892c43b/rules/UNCATEGORIZED/production/yara/APT_HackTool_MSIL_SHARPGOPHER_1.yar#L4-L15"
		license_url = "https://github.com/mandiant/red_team_tool_countermeasures//blob/3561b71724dbfa3e2bb78106aaa2d7f8b892c43b/LICENSE.txt"
		hash = "dd8805d0e470e59b829d98397507d8c2"
		logic_hash = "ac37f77440cb76d7dafa4c9b4130471ca6ca760f6d72691db9ebb8cbaaad0c58"
		score = 75
		quality = 73
		tags = "FILE"
		rev = 2

	strings:
		$typelibguid0 = "83413a89-7f5f-4c3f-805d-f4692bc60173" ascii nocase wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}