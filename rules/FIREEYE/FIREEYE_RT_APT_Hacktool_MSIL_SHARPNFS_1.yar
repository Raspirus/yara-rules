
rule FIREEYE_RT_APT_Hacktool_MSIL_SHARPNFS_1 : FILE
{
	meta:
		description = "The TypeLibGUID present in a .NET binary maps directly to the ProjectGuid found in the '.csproj' file of a .NET project. This rule looks for .NET PE files that contain the ProjectGuid found in the 'sharpnfs' project."
		author = "FireEye"
		id = "b9d1b4e8-644a-5611-85e8-a124f915b443"
		date = "2020-12-09"
		modified = "2020-12-09"
		reference = "https://github.com/mandiant/red_team_tool_countermeasures/"
		source_url = "https://github.com/mandiant/red_team_tool_countermeasures//blob/3561b71724dbfa3e2bb78106aaa2d7f8b892c43b/rules/UNCATEGORIZED/production/yara/APT_HackTool_MSIL_SHARPNFS_1.yar#L4-L15"
		license_url = "https://github.com/mandiant/red_team_tool_countermeasures//blob/3561b71724dbfa3e2bb78106aaa2d7f8b892c43b/LICENSE.txt"
		hash = "dd8805d0e470e59b829d98397507d8c2"
		logic_hash = "e7f9883376b153849970599d9ecc308882eb86a67834cfd8ab06b44539346125"
		score = 75
		quality = 73
		tags = "FILE"
		rev = 3

	strings:
		$typelibguid0 = "9f67ebe3-fc9b-40f2-8a18-5940cfed44cf" ascii nocase wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}