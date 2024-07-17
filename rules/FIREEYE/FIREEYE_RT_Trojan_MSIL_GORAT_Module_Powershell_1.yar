rule FIREEYE_RT_Trojan_MSIL_GORAT_Module_Powershell_1 : FILE
{
	meta:
		description = "The TypeLibGUID present in a .NET binary maps directly to the ProjectGuid found in the '.csproj' file of a .NET project. This rule looks for .NET PE files that contain the ProjectGuid found in the 'RedFlare - Module - PowerShell' project."
		author = "FireEye"
		id = "b0fba130-9cd9-5b7f-a806-9ff8099f5731"
		date = "2020-12-09"
		modified = "2020-12-09"
		reference = "https://github.com/mandiant/red_team_tool_countermeasures/"
		source_url = "https://github.com/mandiant/red_team_tool_countermeasures//blob/3561b71724dbfa3e2bb78106aaa2d7f8b892c43b/rules/REDFLARE (Gorat)/production/yara/Trojan_MSIL_GORAT_Module_PowerShell_1.yar#L4-L16"
		license_url = "https://github.com/mandiant/red_team_tool_countermeasures//blob/3561b71724dbfa3e2bb78106aaa2d7f8b892c43b/LICENSE.txt"
		hash = "dd8805d0e470e59b829d98397507d8c2"
		logic_hash = "e596bc0316a4ef85f04c2683ebc7c94bf9b831843232c33e62c84991e4caeb97"
		score = 75
		quality = 71
		tags = "FILE"
		rev = 1

	strings:
		$typelibguid0 = "38d89034-2dd9-4367-8a6e-5409827a243a" ascii nocase wide
		$typelibguid1 = "845ee9dc-97c9-4c48-834e-dc31ee007c25" ascii nocase wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}