rule FIREEYE_RT_APT_Trojan_Win_REDFLARE_2 : FILE
{
	meta:
		description = "No description has been set in the source file - FireEye-RT"
		author = "FireEye"
		id = "84881e5c-05df-5911-af42-ec82e559588c"
		date = "2020-11-27"
		date = "2020-11-27"
		modified = "2020-12-09"
		reference = "https://github.com/mandiant/red_team_tool_countermeasures/"
		source_url = "https://github.com/mandiant/red_team_tool_countermeasures//blob/3561b71724dbfa3e2bb78106aaa2d7f8b892c43b/rules/REDFLARE/production/yara/APT_Trojan_Win_REDFLARE_2.yar#L4-L20"
		license_url = "https://github.com/mandiant/red_team_tool_countermeasures//blob/3561b71724dbfa3e2bb78106aaa2d7f8b892c43b/LICENSE.txt"
		hash = "9529c4c9773392893a8a0ab8ce8f8ce1,05b99d438dac63a5a993cea37c036673"
		logic_hash = "1f2e1f644b1932486444dfda30b7dad7f50121f59fa493eb8a1a0528ae46db26"
		score = 75
		quality = 75
		tags = "FILE"
		rev = 2

	strings:
		$1 = "initialize" fullword
		$2 = "getData" fullword
		$3 = "putData" fullword
		$4 = "fini" fullword
		$5 = "Cookie: SID1=%s" fullword

	condition:
		( uint16(0)==0x5A4D) and ( uint32( uint32(0x3C))==0x00004550) and all of them
}