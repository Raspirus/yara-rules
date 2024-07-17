rule FIREEYE_RT_Loader_MSIL_Ruralbishop_3 : FILE
{
	meta:
		description = "The TypeLibGUID present in a .NET binary maps directly to the ProjectGuid found in the '.csproj' file of a .NET project. This rule looks for .NET PE files that contain the ProjectGuid found in the public RuralBishop project."
		author = "FireEye"
		id = "55a060ef-74e2-50d9-9090-558aaa04d97d"
		date = "2020-12-09"
		modified = "2020-12-09"
		reference = "https://github.com/mandiant/red_team_tool_countermeasures/"
		source_url = "https://github.com/mandiant/red_team_tool_countermeasures//blob/3561b71724dbfa3e2bb78106aaa2d7f8b892c43b/rules/TRIMBISHOP/production/yara/Loader_MSIL_RuralBishop_3.yar#L4-L15"
		license_url = "https://github.com/mandiant/red_team_tool_countermeasures//blob/3561b71724dbfa3e2bb78106aaa2d7f8b892c43b/LICENSE.txt"
		hash = "09bdbad8358b04994e2c04bb26a160ef"
		logic_hash = "a4c55dede432c249e36e96ca09555448b0343969d389bfdb4bd459fe34e05ea1"
		score = 75
		quality = 73
		tags = "FILE"
		rev = 3

	strings:
		$typelibguid1 = "FE4414D9-1D7E-4EEB-B781-D278FE7A5619" ascii nocase wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and $typelibguid1
}