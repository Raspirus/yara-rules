rule FIREEYE_RT_APT_Hacktool_MSIL_DNSOVERHTTPS_C2_1 : FILE
{
	meta:
		description = "The TypeLibGUID present in a .NET binary maps directly to the ProjectGuid found in the '.csproj' file of a .NET project. This rule looks for .NET PE files that contain the ProjectGuid found in the public 'DoHC2' External C2 project."
		author = "FireEye"
		id = "ee71be6c-e3c8-5365-9f32-157f00066c49"
		date = "2020-12-09"
		modified = "2020-12-09"
		reference = "https://github.com/mandiant/red_team_tool_countermeasures/"
		source_url = "https://github.com/mandiant/red_team_tool_countermeasures//blob/3561b71724dbfa3e2bb78106aaa2d7f8b892c43b/rules/UNCATEGORIZED/production/yara/APT_HackTool_MSIL_DNSOVERHTTPS_C2_1.yar#L4-L16"
		license_url = "https://github.com/mandiant/red_team_tool_countermeasures//blob/3561b71724dbfa3e2bb78106aaa2d7f8b892c43b/LICENSE.txt"
		hash = "dd8805d0e470e59b829d98397507d8c2"
		logic_hash = "a482161bbd8e249977f28466ff1381d4693495f8b8ccd9183ae4fde1ec1471eb"
		score = 75
		quality = 71
		tags = "FILE"
		rev = 2

	strings:
		$typelibguid0 = "5d9515d0-df67-40ed-a6b2-6619620ef0ef" ascii nocase wide
		$typelibguid1 = "7266acbb-b10d-4873-9b99-12d2043b1d4e" ascii nocase wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}