rule FIREEYE_RT_Methodology_OLE_CHARENCODING_2 : FILE
{
	meta:
		description = "Looking for suspicious char encoding"
		author = "FireEye"
		id = "7abd1a11-7a55-50ac-aa6b-537e7c59a5ab"
		date = "2020-12-09"
		modified = "2020-12-09"
		reference = "https://github.com/mandiant/red_team_tool_countermeasures/"
		source_url = "https://github.com/mandiant/red_team_tool_countermeasures//blob/3561b71724dbfa3e2bb78106aaa2d7f8b892c43b/rules/SINFULOFFICE/supplemental/yara/Methodology_OLE_CHARENCODING_2.yar#L4-L23"
		license_url = "https://github.com/mandiant/red_team_tool_countermeasures//blob/3561b71724dbfa3e2bb78106aaa2d7f8b892c43b/LICENSE.txt"
		hash = "41b70737fa8dda75d5e95c82699c2e9b"
		logic_hash = "20843295531dfd88934fe0902a5101c5c0828e82df3289d7f263f16df9c92324"
		score = 65
		quality = 75
		tags = "FILE"
		rev = 4

	strings:
		$echo1 = "101;99;104;111;32;111;102;102;" ascii wide
		$echo2 = "101:99:104:111:32:111:102:102:" ascii wide
		$echo3 = "101x99x104x111x32x111x102x102x" ascii wide
		$pe1 = "77;90;144;" ascii wide
		$pe2 = "77:90:144:" ascii wide
		$pe3 = "77x90x144x" ascii wide
		$pk1 = "80;75;3;4;" ascii wide
		$pk2 = "80:75:3:4:" ascii wide
		$pk3 = "80x75x3x4x" ascii wide

	condition:
		( uint32(0)==0xe011cfd0) and filesize <10MB and any of them
}