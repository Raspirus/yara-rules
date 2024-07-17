
rule FIREEYE_RT_Trojan_MSIL_GORAT_Plugin_DOTNET_1 : FILE
{
	meta:
		description = "The TypeLibGUID present in a .NET binary maps directly to the ProjectGuid found in the '.csproj' file of a .NET project. This rule looks for .NET PE files that contain the ProjectGuid found in the 'RedFlare - Plugin - .NET' project."
		author = "FireEye"
		id = "faa73d64-4bb1-5c06-a3a5-1f1aa99ea932"
		date = "2020-12-09"
		modified = "2020-12-09"
		reference = "https://github.com/mandiant/red_team_tool_countermeasures/"
		source_url = "https://github.com/mandiant/red_team_tool_countermeasures//blob/3561b71724dbfa3e2bb78106aaa2d7f8b892c43b/rules/REDFLARE (Gorat)/production/yara/Trojan_MSIL_GORAT_Plugin_DOTNET_1.yar#L4-L16"
		license_url = "https://github.com/mandiant/red_team_tool_countermeasures//blob/3561b71724dbfa3e2bb78106aaa2d7f8b892c43b/LICENSE.txt"
		hash = "dd8805d0e470e59b829d98397507d8c2"
		logic_hash = "e979822273c6d1ccdfebd341c9e2cb1040fe34a04e8b41c024885063fd946ad5"
		score = 75
		quality = 71
		tags = "FILE"
		rev = 1

	strings:
		$typelibguid0 = "cd9407d0-fc8d-41ed-832d-da94daa3e064" ascii nocase wide
		$typelibguid1 = "fc3daedf-1d01-4490-8032-b978079d8c2d" ascii nocase wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}