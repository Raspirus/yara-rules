
rule FIREEYE_RT_APT_Hacktool_MSIL_SHARPSTOMP_1 : FILE
{
	meta:
		description = "No description has been set in the source file - FireEye-RT"
		author = "FireEye"
		id = "4b4a54c8-9717-5fbb-8130-a49162bc6b07"
		date = "2020-12-02"
		date = "2020-12-02"
		modified = "2020-12-09"
		reference = "https://github.com/mandiant/red_team_tool_countermeasures/"
		source_url = "https://github.com/mandiant/red_team_tool_countermeasures//blob/3561b71724dbfa3e2bb78106aaa2d7f8b892c43b/rules/SHARPSTOMP/production/yara/APT_HackTool_MSIL_SHARPSTOMP_1.yar#L4-L24"
		license_url = "https://github.com/mandiant/red_team_tool_countermeasures//blob/3561b71724dbfa3e2bb78106aaa2d7f8b892c43b/LICENSE.txt"
		hash = "83ed748cd94576700268d35666bf3e01"
		logic_hash = "af8aa0e87d8b6623a908fde5014f3849cd0ca20d5926c798be82ce4eab2668bb"
		score = 75
		quality = 71
		tags = "FILE"
		rev = 3

	strings:
		$s0 = "mscoree.dll" fullword nocase
		$s1 = "timestompfile" fullword nocase
		$s2 = "sharpstomp" fullword nocase
		$s3 = "GetLastWriteTime" fullword
		$s4 = "SetLastWriteTime" fullword
		$s5 = "GetCreationTime" fullword
		$s6 = "SetCreationTime" fullword
		$s7 = "GetLastAccessTime" fullword
		$s8 = "SetLastAccessTime" fullword

	condition:
		( uint16(0)==0x5A4D) and ( uint32( uint32(0x3C))==0x00004550) and all of them
}