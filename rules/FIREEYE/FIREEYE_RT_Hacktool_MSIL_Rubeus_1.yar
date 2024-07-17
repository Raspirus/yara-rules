
rule FIREEYE_RT_Hacktool_MSIL_Rubeus_1 : FILE
{
	meta:
		description = "The TypeLibGUID present in a .NET binary maps directly to the ProjectGuid found in the '.csproj' file of a .NET project. This rule looks for .NET PE files that contain the ProjectGuid found in the public Rubeus project."
		author = "FireEye"
		id = "0ca140ea-2b9f-5904-a4c0-8615229626f0"
		date = "2020-12-09"
		modified = "2020-12-09"
		reference = "https://github.com/mandiant/red_team_tool_countermeasures/"
		source_url = "https://github.com/mandiant/red_team_tool_countermeasures//blob/3561b71724dbfa3e2bb78106aaa2d7f8b892c43b/rules/RUBEUS/production/yara/HackTool_MSIL_Rubeus_1.yar#L4-L15"
		license_url = "https://github.com/mandiant/red_team_tool_countermeasures//blob/3561b71724dbfa3e2bb78106aaa2d7f8b892c43b/LICENSE.txt"
		hash = "66e0681a500c726ed52e5ea9423d2654"
		logic_hash = "ad954f9922ab564d68cb4515b080f6ee69476a8d87f0038e2ae4c222f0e182d7"
		score = 75
		quality = 73
		tags = "FILE"
		rev = 4

	strings:
		$typelibguid = "658C8B7F-3664-4A95-9572-A3E5871DFC06" ascii nocase wide

	condition:
		uint16(0)==0x5A4D and $typelibguid
}