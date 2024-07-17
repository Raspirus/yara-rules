import "pe"


rule FIREEYE_RT_Loader_MSIL_DUEDLLIGENCE_2 : FILE
{
	meta:
		description = "No description has been set in the source file - FireEye-RT"
		author = "FireEye"
		id = "b10b476a-0d38-53e4-80cf-559618729268"
		date = "2020-12-18"
		modified = "2020-12-18"
		reference = "https://github.com/mandiant/red_team_tool_countermeasures/"
		source_url = "https://github.com/mandiant/red_team_tool_countermeasures//blob/3561b71724dbfa3e2bb78106aaa2d7f8b892c43b/rules/DUEDLLIGENCE/production/yara/Loader_MSIL_DUEDLLIGENCE_2.yar#L5-L15"
		license_url = "https://github.com/mandiant/red_team_tool_countermeasures//blob/3561b71724dbfa3e2bb78106aaa2d7f8b892c43b/LICENSE.txt"
		logic_hash = "5a2e0559e3b47c1957a42929fbbeba7a53c21619125381b01dcd8453b6ec4802"
		score = 75
		quality = 75
		tags = "FILE"

	strings:
		$1 = "DueDLLigence" fullword
		$2 = "CPlApplet" fullword
		$iz1 = /_Cor(Exe|Dll)Main/ fullword

	condition:
		( uint16(0)==0x5A4D) and ( uint32( uint32(0x3C))==0x00004550) and all of them
}