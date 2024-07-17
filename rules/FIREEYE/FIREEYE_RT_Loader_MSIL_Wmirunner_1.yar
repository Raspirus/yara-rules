rule FIREEYE_RT_Loader_MSIL_Wmirunner_1 : FILE
{
	meta:
		description = "The TypeLibGUID present in a .NET binary maps directly to the ProjectGuid found in the '.csproj' file of a .NET project. This rule looks for .NET PE files that contain the ProjectGuid found in the 'WMIRunner' project."
		author = "FireEye"
		id = "04c6acfc-859f-5e4a-8c59-9adf08f21657"
		date = "2020-12-09"
		modified = "2020-12-09"
		reference = "https://github.com/mandiant/red_team_tool_countermeasures/"
		source_url = "https://github.com/mandiant/red_team_tool_countermeasures//blob/3561b71724dbfa3e2bb78106aaa2d7f8b892c43b/rules/WMIRUNNER/production/yara/Loader_MSIL_WMIRunner_1.yar#L4-L15"
		license_url = "https://github.com/mandiant/red_team_tool_countermeasures//blob/3561b71724dbfa3e2bb78106aaa2d7f8b892c43b/LICENSE.txt"
		hash = "dd8805d0e470e59b829d98397507d8c2"
		logic_hash = "49d21756a4f0b29909c4b0fa9f3a98dd0480f9401923032de4b3920814b85f29"
		score = 75
		quality = 73
		tags = "FILE"
		rev = 1

	strings:
		$typelibguid0 = "6cc61995-9fd5-4649-b3cc-6f001d60ceda" ascii nocase wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}