rule FIREEYE_RT_APT_Hacktool_MSIL_LUALOADER_1 : FILE
{
	meta:
		description = "The TypeLibGUID present in a .NET binary maps directly to the ProjectGuid found in the '.csproj' file of a .NET project. This rule looks for .NET PE files that contain the ProjectGuid found in the 'lualoader' project."
		author = "FireEye"
		id = "e8480cf8-1852-5572-8e92-c0ae676b7507"
		date = "2020-12-09"
		modified = "2020-12-09"
		reference = "https://github.com/mandiant/red_team_tool_countermeasures/"
		source_url = "https://github.com/mandiant/red_team_tool_countermeasures//blob/3561b71724dbfa3e2bb78106aaa2d7f8b892c43b/rules/LUALOADER/production/yara/APT_HackTool_MSIL_LUALOADER_1.yar#L4-L15"
		license_url = "https://github.com/mandiant/red_team_tool_countermeasures//blob/3561b71724dbfa3e2bb78106aaa2d7f8b892c43b/LICENSE.txt"
		hash = "dd8805d0e470e59b829d98397507d8c2"
		logic_hash = "7e9f9836ec91aa66c8779588cfceff718487f0cb5048d17538c947aba687a4cf"
		score = 75
		quality = 73
		tags = "FILE"
		rev = 3

	strings:
		$typelibguid0 = "8b546b49-2b2c-4577-a323-76dc713fe2ea" ascii nocase wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}