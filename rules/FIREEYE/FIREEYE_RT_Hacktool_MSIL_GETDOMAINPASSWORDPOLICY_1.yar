
rule FIREEYE_RT_Hacktool_MSIL_GETDOMAINPASSWORDPOLICY_1 : FILE
{
	meta:
		description = "The TypeLibGUID present in a .NET binary maps directly to the ProjectGuid found in the '.csproj' file of a .NET project. This rule looks for .NET PE files that contain the ProjectGuid found in the recon utility 'getdomainpasswordpolicy' project."
		author = "FireEye"
		id = "69745e99-33cc-5171-ae7a-5c98439a0b6d"
		date = "2020-12-09"
		modified = "2020-12-09"
		reference = "https://github.com/mandiant/red_team_tool_countermeasures/"
		source_url = "https://github.com/mandiant/red_team_tool_countermeasures//blob/3561b71724dbfa3e2bb78106aaa2d7f8b892c43b/rules/GETDOMAINPASSWORDPOLICY/production/yara/HackTool_MSIL_GETDOMAINPASSWORDPOLICY_1.yar#L4-L15"
		license_url = "https://github.com/mandiant/red_team_tool_countermeasures//blob/3561b71724dbfa3e2bb78106aaa2d7f8b892c43b/LICENSE.txt"
		hash = "dd8805d0e470e59b829d98397507d8c2"
		logic_hash = "6b2ea3ebfea2c87f16052f4a43b64eb2d595c2dd4a64d45dfce1642668dcf602"
		score = 75
		quality = 73
		tags = "FILE"
		rev = 4

	strings:
		$typelibguid0 = "a5da1897-29aa-45f4-a924-561804276f08" ascii nocase wide

	condition:
		filesize <10MB and ( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}