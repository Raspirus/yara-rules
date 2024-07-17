
rule FIREEYE_RT_Builder_MSIL_G2JS_1 : FILE
{
	meta:
		description = "The TypeLibGUID present in a .NET binary maps directly to the ProjectGuid found in the '.csproj' file of a .NET project. This rule looks for .NET PE files that contain the ProjectGuid found in the Gadget2JScript project."
		author = "FireEye"
		id = "484202c2-ac7d-5e6c-8bf1-3452a357c668"
		date = "2020-12-09"
		modified = "2020-12-09"
		reference = "https://github.com/mandiant/red_team_tool_countermeasures/"
		source_url = "https://github.com/mandiant/red_team_tool_countermeasures//blob/3561b71724dbfa3e2bb78106aaa2d7f8b892c43b/rules/G2JS/production/yara/Builder_MSIL_G2JS_1.yar#L4-L15"
		license_url = "https://github.com/mandiant/red_team_tool_countermeasures//blob/3561b71724dbfa3e2bb78106aaa2d7f8b892c43b/LICENSE.txt"
		hash = "fa255fdc88ab656ad9bc383f9b322a76"
		logic_hash = "487d8e8deef218412f241d99ce32b63bfeb3568d23048b9dd4afff8f401bfea5"
		score = 75
		quality = 73
		tags = "FILE"
		rev = 2

	strings:
		$typelibguid1 = "AF9C62A1-F8D2-4BE0-B019-0A7873E81EA9" ascii nocase wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and $typelibguid1
}