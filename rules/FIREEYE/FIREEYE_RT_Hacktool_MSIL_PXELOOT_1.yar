
rule FIREEYE_RT_Hacktool_MSIL_PXELOOT_1 : FILE
{
	meta:
		description = "The TypeLibGUID present in a .NET binary maps directly to the ProjectGuid found in the '.csproj' file of a .NET project. This rule looks for .NET PE files that contain the ProjectGuid found in the PXE And Loot project."
		author = "FireEye"
		id = "5a72a6ff-bae4-57f5-a19b-a4595ac57293"
		date = "2020-12-09"
		modified = "2020-12-09"
		reference = "https://github.com/mandiant/red_team_tool_countermeasures/"
		source_url = "https://github.com/mandiant/red_team_tool_countermeasures//blob/3561b71724dbfa3e2bb78106aaa2d7f8b892c43b/rules/PXELOOT/production/yara/HackTool_MSIL_PXELOOT_1.yar#L4-L15"
		license_url = "https://github.com/mandiant/red_team_tool_countermeasures//blob/3561b71724dbfa3e2bb78106aaa2d7f8b892c43b/LICENSE.txt"
		hash = "82e33011ac34adfcced6cddc8ea56a81"
		logic_hash = "c9892adcb9ff5471235e45988f6662d3b8f984fdafca7024a5781eed50f6c0b3"
		score = 75
		quality = 73
		tags = "FILE"
		rev = 7

	strings:
		$typelibguid1 = "78B2197B-2E56-425A-9585-56EDC2C797D6" ascii nocase wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and $typelibguid1
}