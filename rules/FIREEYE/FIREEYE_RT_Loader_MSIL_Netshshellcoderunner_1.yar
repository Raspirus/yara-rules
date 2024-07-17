
rule FIREEYE_RT_Loader_MSIL_Netshshellcoderunner_1 : FILE
{
	meta:
		description = "The TypeLibGUID present in a .NET binary maps directly to the ProjectGuid found in the '.csproj' file of a .NET project. This rule looks for .NET PE files that contain the ProjectGuid found in the 'NetshShellCodeRunner' project."
		author = "FireEye"
		id = "b3521812-7ea3-5f80-89bd-3bdd71b687f2"
		date = "2020-12-09"
		modified = "2020-12-09"
		reference = "https://github.com/mandiant/red_team_tool_countermeasures/"
		source_url = "https://github.com/mandiant/red_team_tool_countermeasures//blob/3561b71724dbfa3e2bb78106aaa2d7f8b892c43b/rules/NETSHSHELLCODERUNNER/production/yara/Loader_MSIL_NetshShellCodeRunner_1.yar#L4-L15"
		license_url = "https://github.com/mandiant/red_team_tool_countermeasures//blob/3561b71724dbfa3e2bb78106aaa2d7f8b892c43b/LICENSE.txt"
		hash = "dd8805d0e470e59b829d98397507d8c2"
		logic_hash = "97f6475a9d42697f633e06a9b04a85021ca4920145eb4af257d71b431448f0e9"
		score = 75
		quality = 73
		tags = "FILE"
		rev = 2

	strings:
		$typelibguid0 = "49c045bc-59bb-4a00-85c3-4beb59b2ee12" ascii nocase wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}