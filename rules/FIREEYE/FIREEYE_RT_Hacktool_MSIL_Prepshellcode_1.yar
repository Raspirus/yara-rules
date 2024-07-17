rule FIREEYE_RT_Hacktool_MSIL_Prepshellcode_1 : FILE
{
	meta:
		description = "The TypeLibGUID present in a .NET binary maps directly to the ProjectGuid found in the '.csproj' file of a .NET project. This rule looks for .NET PE files that contain the ProjectGuid found in the 'PrepShellcode' project."
		author = "FireEye"
		id = "32fb6b1d-e01f-5555-8516-088dca2166cf"
		date = "2020-12-09"
		modified = "2020-12-09"
		reference = "https://github.com/mandiant/red_team_tool_countermeasures/"
		source_url = "https://github.com/mandiant/red_team_tool_countermeasures//blob/3561b71724dbfa3e2bb78106aaa2d7f8b892c43b/rules/PREPSHELLCODE/production/yara/HackTool_MSIL_PrepShellcode_1.yar#L4-L15"
		license_url = "https://github.com/mandiant/red_team_tool_countermeasures//blob/3561b71724dbfa3e2bb78106aaa2d7f8b892c43b/LICENSE.txt"
		hash = "dd8805d0e470e59b829d98397507d8c2"
		logic_hash = "aedae87d84275f6589c982c04175ddc0aee3e4f3ae959ced4b4e2294675522e6"
		score = 75
		quality = 73
		tags = "FILE"
		rev = 2

	strings:
		$typelibguid0 = "d16ed275-70d5-4ae5-8ce7-d249f967616c" ascii nocase wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}