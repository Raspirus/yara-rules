rule FIREEYE_RT_APT_Hacktool_MSIL_SHARPDNS_1 : FILE
{
	meta:
		description = "The TypeLibGUID present in a .NET binary maps directly to the ProjectGuid found in the '.csproj' file of a .NET project. This rule looks for .NET PE files that contain the ProjectGuid found in the 'sharpdns' project."
		author = "FireEye"
		id = "db6b45be-f42f-5d0f-b50a-32e7a2cbfce6"
		date = "2020-12-09"
		modified = "2020-12-09"
		reference = "https://github.com/mandiant/red_team_tool_countermeasures/"
		source_url = "https://github.com/mandiant/red_team_tool_countermeasures//blob/3561b71724dbfa3e2bb78106aaa2d7f8b892c43b/rules/UNCATEGORIZED/production/yara/APT_HackTool_MSIL_SHARPDNS_1.yar#L4-L15"
		license_url = "https://github.com/mandiant/red_team_tool_countermeasures//blob/3561b71724dbfa3e2bb78106aaa2d7f8b892c43b/LICENSE.txt"
		hash = "dd8805d0e470e59b829d98397507d8c2"
		logic_hash = "bab36f9b1532c3b24c2aea2907006820ed7cf1c90dae7a8138962e14ac9eff55"
		score = 75
		quality = 73
		tags = "FILE"
		rev = 2

	strings:
		$typelibguid0 = "d888cec8-7562-40e9-9c76-2bb9e43bb634" ascii nocase wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}