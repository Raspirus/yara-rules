rule FIREEYE_RT_APT_Downloader_Win64_REDFLARE_1 : FILE
{
	meta:
		description = "No description has been set in the source file - FireEye-RT"
		author = "FireEye"
		id = "15a5e22b-84b0-5b36-8772-1d496ac447b2"
		date = "2020-11-27"
		date = "2020-11-27"
		modified = "2020-12-09"
		reference = "https://github.com/mandiant/red_team_tool_countermeasures/"
		source_url = "https://github.com/mandiant/red_team_tool_countermeasures//blob/3561b71724dbfa3e2bb78106aaa2d7f8b892c43b/rules/REDFLARE/production/yara/APT_Downloader_Win64_REDFLARE_1.yar#L4-L17"
		license_url = "https://github.com/mandiant/red_team_tool_countermeasures//blob/3561b71724dbfa3e2bb78106aaa2d7f8b892c43b/LICENSE.txt"
		hash = "9529c4c9773392893a8a0ab8ce8f8ce1"
		logic_hash = "1b9bece6083403615841c752eac48fd20095e918d6e175563dd122be2885d875"
		score = 75
		quality = 75
		tags = "FILE"
		rev = 2

	strings:
		$const = "Cookie: SID1=%s" fullword
		$http_req = { 00 00 08 80 81 3D [4] BB 01 00 00 75 [1-10] 00 00 80 00 [1-4] 00 10 00 00 [1-4] 00 20 00 00 89 [6-20] 00 00 00 00 [6-20] 00 00 00 00 [2-10] 00 00 00 00 45 33 C9 [4-20] 48 8D 15 [4] 48 8B 0D [4] FF 15 [4-50] B9 14 00 00 00 E8 }

	condition:
		( uint16(0)==0x5A4D) and ( uint32( uint32(0x3C))==0x00004550) and ( uint16( uint32(0x3C)+0x18)==0x020B) and all of them
}