rule FIREEYE_RT_APT_Hacktool_MSIL_SHARPSTOMP_2 : FILE
{
	meta:
		description = "No description has been set in the source file - FireEye-RT"
		author = "FireEye"
		id = "d1a3477d-55c6-5c33-bd65-5b1e0d65f24b"
		date = "2020-12-02"
		date = "2020-12-02"
		modified = "2020-12-09"
		reference = "https://github.com/mandiant/red_team_tool_countermeasures/"
		source_url = "https://github.com/mandiant/red_team_tool_countermeasures//blob/3561b71724dbfa3e2bb78106aaa2d7f8b892c43b/rules/SHARPSTOMP/production/yara/APT_HackTool_MSIL_SHARPSTOMP_2.yar#L4-L22"
		license_url = "https://github.com/mandiant/red_team_tool_countermeasures//blob/3561b71724dbfa3e2bb78106aaa2d7f8b892c43b/LICENSE.txt"
		hash = "83ed748cd94576700268d35666bf3e01"
		logic_hash = "4ed1553f12c607792d7d4e7026ecb36231cd417a06eba8b2925c2c643436b5fe"
		score = 75
		quality = 75
		tags = "FILE"
		rev = 3

	strings:
		$f0 = "mscoree.dll" fullword nocase
		$s0 = { 06 72 [4] 6F [4] 2C ?? 06 72 [4] 6F [4] 2D ?? 72 [4] 28 [4] 28 [4] 2A }
		$s1 = { 02 28 [4] 0A 02 28 [4] 0B 02 28 [4] 0C 72 [4] 28 [4] 72 }
		$s2 = { 28 [4] 02 28 [4] 0D 12 ?? 03 6C 28 [4] 28 [4] 02 28 [4] 0D 12 ?? 03 6C 28 [4] 28 [4] 02 28 [4] 0D 12 ?? 03 6C 28 [4] 28 [4] 72 }
		$s3 = "SetCreationTime" fullword
		$s4 = "GetLastAccessTime" fullword
		$s5 = "SetLastAccessTime" fullword

	condition:
		( uint16(0)==0x5A4D) and ( uint32( uint32(0x3C))==0x00004550) and all of them
}