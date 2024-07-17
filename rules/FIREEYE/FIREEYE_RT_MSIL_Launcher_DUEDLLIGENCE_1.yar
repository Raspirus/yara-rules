rule FIREEYE_RT_MSIL_Launcher_DUEDLLIGENCE_1 : FILE
{
	meta:
		description = "The TypeLibGUID present in a .NET binary maps directly to the ProjectGuid found in the '.csproj' file of a .NET project. This rule looks for .NET PE files that contain the ProjectGuid found in the 'DUEDLLIGENCE' project."
		author = "FireEye"
		id = "86f0ebe5-110b-53e2-bba5-676f00c2cddd"
		date = "2020-12-09"
		modified = "2020-12-09"
		reference = "https://github.com/mandiant/red_team_tool_countermeasures/"
		source_url = "https://github.com/mandiant/red_team_tool_countermeasures//blob/3561b71724dbfa3e2bb78106aaa2d7f8b892c43b/rules/DUEDLLIGENCE/production/yara/MSIL_Launcher_DUEDLLIGENCE_1.yar#L4-L15"
		license_url = "https://github.com/mandiant/red_team_tool_countermeasures//blob/3561b71724dbfa3e2bb78106aaa2d7f8b892c43b/LICENSE.txt"
		hash = "a91bf61cc18705be2288a0f6f125068f"
		logic_hash = "bd6abaa909f0c776d81ed1115e875888336661c91df3881f4f3ea5dd27e115f8"
		score = 75
		quality = 73
		tags = "FILE"
		rev = 1

	strings:
		$typelibguid0 = "73948912-cebd-48ed-85e2-85fcd1d4f560" ascii nocase wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}