rule FIREEYE_RT_APT_Hacktool_MSIL_JUSTASK_1 : FILE
{
	meta:
		description = "The TypeLibGUID present in a .NET binary maps directly to the ProjectGuid found in the '.csproj' file of a .NET project. This rule looks for .NET PE files that contain the ProjectGuid found in the 'justask' project."
		author = "FireEye"
		id = "06a03d82-db69-5b5a-a578-a8053814e917"
		date = "2020-12-09"
		modified = "2020-12-09"
		reference = "https://github.com/mandiant/red_team_tool_countermeasures/"
		source_url = "https://github.com/mandiant/red_team_tool_countermeasures//blob/3561b71724dbfa3e2bb78106aaa2d7f8b892c43b/rules/JUSTASK/production/yara/APT_HackTool_MSIL_JUSTASK_1.yar#L4-L15"
		license_url = "https://github.com/mandiant/red_team_tool_countermeasures//blob/3561b71724dbfa3e2bb78106aaa2d7f8b892c43b/LICENSE.txt"
		hash = "dd8805d0e470e59b829d98397507d8c2"
		logic_hash = "24d2f8e3838c4f02cd80644a396ce7cf105761d2feba54e39973564ca5e97571"
		score = 75
		quality = 73
		tags = "FILE"
		rev = 2

	strings:
		$typelibguid0 = "aa59be52-7845-4fed-9ea5-1ea49085d67a" ascii nocase wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}