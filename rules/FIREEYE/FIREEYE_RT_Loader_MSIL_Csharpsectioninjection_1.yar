rule FIREEYE_RT_Loader_MSIL_Csharpsectioninjection_1 : FILE
{
	meta:
		description = "The TypeLibGUID present in a .NET binary maps directly to the ProjectGuid found in the '.csproj' file of a .NET project. This rule looks for .NET PE files that contain the ProjectGuid found in the 'C_Sharp_SectionInjection' project."
		author = "FireEye"
		id = "ca5bf5cd-1950-53ed-8984-e880a15e658e"
		date = "2020-12-09"
		modified = "2020-12-09"
		reference = "https://github.com/mandiant/red_team_tool_countermeasures/"
		source_url = "https://github.com/mandiant/red_team_tool_countermeasures//blob/3561b71724dbfa3e2bb78106aaa2d7f8b892c43b/rules/SHARPSECTIONINJECTION/production/yara/Loader_MSIL_CSharpSectionInjection_1.yar#L4-L15"
		license_url = "https://github.com/mandiant/red_team_tool_countermeasures//blob/3561b71724dbfa3e2bb78106aaa2d7f8b892c43b/LICENSE.txt"
		hash = "dd8805d0e470e59b829d98397507d8c2"
		logic_hash = "011cf4dffe6ef90a79cdfabb0e297152c00b0404b1801f56fd7e703ab90b1692"
		score = 75
		quality = 73
		tags = "FILE"
		rev = 2

	strings:
		$typelibguid0 = "d77135da-0496-4b5c-9afe-e1590a4c136a" ascii nocase wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}