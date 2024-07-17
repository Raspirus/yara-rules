
rule FIREEYE_RT_Loader_MSIL_Wildchild_1 : FILE
{
	meta:
		description = "The TypeLibGUID present in a .NET binary maps directly to the ProjectGuid found in the '.csproj' file of a .NET project. This rule looks for .NET PE files that contain the ProjectGuid found in the WildChild project."
		author = "FireEye"
		id = "350dd658-46c9-573b-b532-07e4b437ba8d"
		date = "2020-12-09"
		modified = "2020-12-09"
		reference = "https://github.com/mandiant/red_team_tool_countermeasures/"
		source_url = "https://github.com/mandiant/red_team_tool_countermeasures//blob/3561b71724dbfa3e2bb78106aaa2d7f8b892c43b/rules/WILDCHILD/production/yara/Loader_MSIL_WildChild_1.yar#L4-L15"
		license_url = "https://github.com/mandiant/red_team_tool_countermeasures//blob/3561b71724dbfa3e2bb78106aaa2d7f8b892c43b/LICENSE.txt"
		hash = "7e6bc0ed11c2532b2ae7060327457812"
		logic_hash = "e4320e33770613542182518ec787e4ccbb32f83c8afca5ec957d4846e6f4eb04"
		score = 75
		quality = 73
		tags = "FILE"
		rev = 4

	strings:
		$typelibguid1 = "2e71d5ff-ece4-4006-9e98-37bb724a7780" ascii nocase wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and $typelibguid1
}