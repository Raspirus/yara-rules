rule FIREEYE_RT_APT_Trojan_Win_REDFLARE_3 : FILE
{
	meta:
		description = "No description has been set in the source file - FireEye-RT"
		author = "FireEye"
		id = "2f6785c4-f4d0-52ff-8c46-da953e2ca92a"
		date = "2020-12-01"
		date = "2020-12-01"
		modified = "2020-12-09"
		reference = "https://github.com/mandiant/red_team_tool_countermeasures/"
		source_url = "https://github.com/mandiant/red_team_tool_countermeasures//blob/3561b71724dbfa3e2bb78106aaa2d7f8b892c43b/rules/REDFLARE/production/yara/APT_Trojan_Win_REDFLARE_3.yar#L4-L19"
		license_url = "https://github.com/mandiant/red_team_tool_countermeasures//blob/3561b71724dbfa3e2bb78106aaa2d7f8b892c43b/LICENSE.txt"
		hash = "9ccda4d7511009d5572ef2f8597fba4e,ece07daca53dd0a7c23dacabf50f56f1"
		logic_hash = "ee104bc145686a134e4d6d620dae7d1dacff7645d47f1a8d7a212327352b8e87"
		score = 75
		quality = 75
		tags = "FILE"
		rev = 1

	strings:
		$calc_image_size = { 28 00 00 00 [2-30] 83 E2 1F [4-20] C1 F8 05 [0-8] 0F AF C? [0-30] C1 E0 02 }
		$str1 = "CreateCompatibleBitmap" fullword
		$str2 = "BitBlt" fullword
		$str3 = "runCommand" fullword

	condition:
		( uint16(0)==0x5A4D) and ( uint32( uint32(0x3C))==0x00004550) and all of them
}