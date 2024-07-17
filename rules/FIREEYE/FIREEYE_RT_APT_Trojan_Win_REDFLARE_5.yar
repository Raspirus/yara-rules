rule FIREEYE_RT_APT_Trojan_Win_REDFLARE_5 : FILE
{
	meta:
		description = "No description has been set in the source file - FireEye-RT"
		author = "FireEye"
		id = "892981d6-f310-5ee8-95b5-dd4bd720a86c"
		date = "2020-12-01"
		date = "2020-12-01"
		modified = "2020-12-09"
		reference = "https://github.com/mandiant/red_team_tool_countermeasures/"
		source_url = "https://github.com/mandiant/red_team_tool_countermeasures//blob/3561b71724dbfa3e2bb78106aaa2d7f8b892c43b/rules/REDFLARE/production/yara/APT_Trojan_Win_REDFLARE_5.yar#L4-L20"
		license_url = "https://github.com/mandiant/red_team_tool_countermeasures//blob/3561b71724dbfa3e2bb78106aaa2d7f8b892c43b/LICENSE.txt"
		hash = "dfbb1b988c239ade4c23856e42d4127b, 3322fba40c4de7e3de0fda1123b0bf5d"
		logic_hash = "ab38e5ebded026829672941709797b40f8e13fb244b6a8ed3545de4358f727b8"
		score = 75
		quality = 75
		tags = "FILE"
		rev = 3

	strings:
		$s1 = "AdjustTokenPrivileges" fullword
		$s2 = "LookupPrivilegeValueW" fullword
		$s3 = "ImpersonateLoggedOnUser" fullword
		$s4 = "runCommand" fullword
		$steal_token = { FF 15 [4] 85 C0 [1-40] C7 44 24 ?? 01 00 00 00 [0-20] C7 44 24 ?? 02 00 00 00 [0-20] FF 15 [4] FF [1-5] 85 C0 [4-40] 00 04 00 00 FF 15 [4-5] 85 C0 [2-20] ( BA 0F 00 00 00 | 6A 0F ) [1-4] FF 15 [4] 85 C0 74 [1-20] FF 15 [4] 85 C0 74 [1-20] ( 6A 0B | B9 0B 00 00 00 ) E8 }

	condition:
		( uint16(0)==0x5A4D) and ( uint32( uint32(0x3C))==0x00004550) and all of them
}