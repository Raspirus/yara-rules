rule FIREEYE_RT_APT_Hacktool_MSIL_REVOLVER_1 : FILE
{
	meta:
		description = "The TypeLibGUID present in a .NET binary maps directly to the ProjectGuid found in the '.csproj' file of a .NET project. This rule looks for .NET PE files that contain the ProjectGuid found in the 'revolver' project."
		author = "FireEye"
		id = "8fa5adb7-dc66-51bc-9f60-2308515f33a8"
		date = "2020-12-09"
		modified = "2020-12-09"
		reference = "https://github.com/mandiant/red_team_tool_countermeasures/"
		source_url = "https://github.com/mandiant/red_team_tool_countermeasures//blob/3561b71724dbfa3e2bb78106aaa2d7f8b892c43b/rules/REVOLVER/production/yara/APT_HackTool_MSIL_REVOLVER_1.yar#L4-L16"
		license_url = "https://github.com/mandiant/red_team_tool_countermeasures//blob/3561b71724dbfa3e2bb78106aaa2d7f8b892c43b/LICENSE.txt"
		hash = "dd8805d0e470e59b829d98397507d8c2"
		logic_hash = "8df8a56ed55b7857adb95daa643d544a49eb5f1952b4ad3ef757c34dad2ce317"
		score = 75
		quality = 71
		tags = "FILE"
		rev = 2

	strings:
		$typelibguid0 = "a8bdbba4-7291-49d1-9a1b-372de45a9d88" ascii nocase wide
		$typelibguid1 = "b214d962-7595-440b-abef-f83ecdb999d2" ascii nocase wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}