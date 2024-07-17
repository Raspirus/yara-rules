rule FIREEYE_RT_APT_Hacktool_MSIL_NOAMCI_1 : FILE
{
	meta:
		description = "The TypeLibGUID present in a .NET binary maps directly to the ProjectGuid found in the '.csproj' file of a .NET project. This rule looks for .NET PE files that contain the ProjectGuid found in the 'noamci' project."
		author = "FireEye"
		id = "48066258-528f-5a70-81e1-15d6dfd9ff4f"
		date = "2020-12-09"
		modified = "2020-12-09"
		reference = "https://github.com/mandiant/red_team_tool_countermeasures/"
		source_url = "https://github.com/mandiant/red_team_tool_countermeasures//blob/3561b71724dbfa3e2bb78106aaa2d7f8b892c43b/rules/NOAMCI/production/yara/APT_HackTool_MSIL_NOAMCI_1.yar#L4-L16"
		license_url = "https://github.com/mandiant/red_team_tool_countermeasures//blob/3561b71724dbfa3e2bb78106aaa2d7f8b892c43b/LICENSE.txt"
		hash = "dd8805d0e470e59b829d98397507d8c2"
		logic_hash = "6278cfb4e9af20bbe943f4b99227c7fba276315a9f0059575b3ed4ef96a848c4"
		score = 75
		quality = 71
		tags = "FILE"
		rev = 4

	strings:
		$typelibguid0 = "7bcccf21-7ecd-4fd4-8f77-06d461fd4d51" ascii nocase wide
		$typelibguid1 = "ef86214e-54de-41c3-b27f-efc61d0accc3" ascii nocase wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}