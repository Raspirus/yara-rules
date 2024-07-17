rule FIREEYE_RT_Hacktool_MSIL_HOLSTER_1 : FILE
{
	meta:
		description = "The TypeLibGUID present in a .NET binary maps directly to the ProjectGuid found in the '.csproj' file of a .NET project. This rule looks for .NET PE files that contain the ProjectGuid found in the a customized version of the 'DUEDLLIGENCE' project."
		author = "FireEye"
		id = "e1e8979e-2dee-5061-a11d-00dcfba476c3"
		date = "2020-12-09"
		modified = "2020-12-09"
		reference = "https://github.com/mandiant/red_team_tool_countermeasures/"
		source_url = "https://github.com/mandiant/red_team_tool_countermeasures//blob/3561b71724dbfa3e2bb78106aaa2d7f8b892c43b/rules/DUEDLLIGENCE/production/yara/HackTool_MSIL_HOLSTER_1.yar#L4-L15"
		license_url = "https://github.com/mandiant/red_team_tool_countermeasures//blob/3561b71724dbfa3e2bb78106aaa2d7f8b892c43b/LICENSE.txt"
		hash = "a91bf61cc18705be2288a0f6f125068f"
		logic_hash = "bc254a1ab71f2a6092f139ce5a85347a7a4976f963603ffbbebb9b0d6ce6573c"
		score = 75
		quality = 73
		tags = "FILE"
		rev = 2

	strings:
		$typelibguid1 = "a8bdbba4-7291-49d1-9a1b-372de45a9d88" ascii nocase wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}