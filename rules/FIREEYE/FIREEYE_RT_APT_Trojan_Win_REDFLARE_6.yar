
rule FIREEYE_RT_APT_Trojan_Win_REDFLARE_6 : FILE
{
	meta:
		description = "No description has been set in the source file - FireEye-RT"
		author = "FireEye"
		id = "5875a9ec-c3ee-57f0-a430-4443db585def"
		date = "2020-12-01"
		date = "2020-12-01"
		modified = "2020-12-09"
		reference = "https://github.com/mandiant/red_team_tool_countermeasures/"
		source_url = "https://github.com/mandiant/red_team_tool_countermeasures//blob/3561b71724dbfa3e2bb78106aaa2d7f8b892c43b/rules/REDFLARE/supplemental/yara/APT_Trojan_Win_REDFLARE_6.yar#L4-L20"
		license_url = "https://github.com/mandiant/red_team_tool_countermeasures//blob/3561b71724dbfa3e2bb78106aaa2d7f8b892c43b/LICENSE.txt"
		hash = "294b1e229c3b1efce29b162e7b3be0ab, 6902862bd81da402e7ac70856afbe6a2"
		logic_hash = "1e6f8320e0c0b601fc72fa4d9c61e46adfbcd84638c97da5988ca848e036312a"
		score = 75
		quality = 75
		tags = "FILE"
		rev = 2

	strings:
		$s1 = "RevertToSelf" fullword
		$s2 = "Unsuccessful" fullword
		$s3 = "Successful" fullword
		$s4 = "runCommand" fullword
		$s5 = "initialize" fullword

	condition:
		( uint16(0)==0x5A4D) and ( uint32( uint32(0x3C))==0x00004550) and all of them
}