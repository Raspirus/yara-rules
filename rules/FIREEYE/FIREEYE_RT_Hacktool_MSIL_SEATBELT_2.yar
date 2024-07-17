
rule FIREEYE_RT_Hacktool_MSIL_SEATBELT_2 : FILE
{
	meta:
		description = "The TypeLibGUID present in a .NET binary maps directly to the ProjectGuid found in the '.csproj' file of a .NET project. This rule looks for .NET PE files that contain the ProjectGuid found in the public SeatBelt project."
		author = "FireEye"
		id = "225b42fe-c73a-59c0-a1f4-1d6dff6e76e1"
		date = "2020-12-09"
		modified = "2020-12-09"
		reference = "https://github.com/mandiant/red_team_tool_countermeasures/"
		source_url = "https://github.com/mandiant/red_team_tool_countermeasures//blob/3561b71724dbfa3e2bb78106aaa2d7f8b892c43b/rules/BELTALOWDA/production/yara/HackTool_MSIL_SEATBELT_2.yar#L4-L15"
		license_url = "https://github.com/mandiant/red_team_tool_countermeasures//blob/3561b71724dbfa3e2bb78106aaa2d7f8b892c43b/LICENSE.txt"
		hash = "9f401176a9dd18fa2b5b90b4a2aa1356"
		logic_hash = "e48474c5025fd88e3c2824e1e943ff56cde0ea05984aad0249ccf73caa6d4a36"
		score = 75
		quality = 73
		tags = "FILE"
		rev = 3

	strings:
		$typelibguid1 = "AEC32155-D589-4150-8FE7-2900DF4554C8" ascii nocase wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and $typelibguid1
}