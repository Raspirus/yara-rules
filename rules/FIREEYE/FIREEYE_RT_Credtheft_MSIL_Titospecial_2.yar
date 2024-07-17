rule FIREEYE_RT_Credtheft_MSIL_Titospecial_2 : FILE
{
	meta:
		description = "The TypeLibGUID present in a .NET binary maps directly to the ProjectGuid found in the '.csproj' file of a .NET project. This rule looks for .NET PE files that contain the ProjectGuid found in the TitoSpecial project. There are 2 GUIDs in this rule as the x86 and x64 versions of this tool use a different ProjectGuid."
		author = "FireEye"
		id = "0262c720-e6b8-5bf2-a242-19a7f044973f"
		date = "2020-12-09"
		modified = "2020-12-09"
		reference = "https://github.com/mandiant/red_team_tool_countermeasures/"
		source_url = "https://github.com/mandiant/red_team_tool_countermeasures//blob/3561b71724dbfa3e2bb78106aaa2d7f8b892c43b/rules/TITOSPECIAL/production/yara/CredTheft_MSIL_TitoSpecial_2.yar#L4-L16"
		license_url = "https://github.com/mandiant/red_team_tool_countermeasures//blob/3561b71724dbfa3e2bb78106aaa2d7f8b892c43b/LICENSE.txt"
		hash = "4bf96a7040a683bd34c618431e571e26"
		logic_hash = "2f621f8de2a4679e6cbce7f41859eaa3095ca54090c8bfccd3b767590ac91f2c"
		score = 75
		quality = 71
		tags = "FILE"
		rev = 4

	strings:
		$typelibguid1 = "C6D94B4C-B063-4DEB-A83A-397BA08515D3" ascii nocase wide
		$typelibguid2 = "3b5320cf-74c1-494e-b2c8-a94a24380e60" ascii nocase wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and ($typelibguid1 or $typelibguid2)
}