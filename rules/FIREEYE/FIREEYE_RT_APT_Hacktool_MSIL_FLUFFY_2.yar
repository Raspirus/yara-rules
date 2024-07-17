rule FIREEYE_RT_APT_Hacktool_MSIL_FLUFFY_2 : FILE
{
	meta:
		description = "No description has been set in the source file - FireEye-RT"
		author = "FireEye"
		id = "ce39710e-7649-5f7d-bbbe-65dc30f678e8"
		date = "2020-12-04"
		date = "2020-12-04"
		modified = "2020-12-09"
		reference = "https://github.com/mandiant/red_team_tool_countermeasures/"
		source_url = "https://github.com/mandiant/red_team_tool_countermeasures//blob/3561b71724dbfa3e2bb78106aaa2d7f8b892c43b/rules/FLUFFY/production/yara/APT_HackTool_MSIL_FLUFFY_2.yar#L4-L21"
		license_url = "https://github.com/mandiant/red_team_tool_countermeasures//blob/3561b71724dbfa3e2bb78106aaa2d7f8b892c43b/LICENSE.txt"
		hash = "11b5aceb428c3e8c61ed24a8ca50553e"
		logic_hash = "872ab717668375a49d6c7b1927a680747b405c0198fe4fc6f43ccc562870eb37"
		score = 75
		quality = 75
		tags = "FILE"
		rev = 1

	strings:
		$s1 = "\x00Asktgt\x00"
		$s2 = "\x00Kerberoast\x00"
		$s3 = "\x00HarvestCommand\x00"
		$s4 = "\x00EnumerateTickets\x00"
		$s5 = "[*] Action: " wide
		$s6 = "\x00Fluffy.Commands\x00"

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and all of them
}