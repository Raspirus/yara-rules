
rule FIREEYE_RT_APT_Trojan_Linux_REDFLARE_1 : FILE
{
	meta:
		description = "No description has been set in the source file - FireEye-RT"
		author = "FireEye"
		id = "220302bc-4ed3-5e10-9bd2-a8ed2bdaef73"
		date = "2020-12-02"
		date = "2020-12-02"
		modified = "2020-12-09"
		reference = "https://github.com/mandiant/red_team_tool_countermeasures/"
		source_url = "https://github.com/mandiant/red_team_tool_countermeasures//blob/3561b71724dbfa3e2bb78106aaa2d7f8b892c43b/rules/REDFLARE/supplemental/yara/APT_Trojan_Linux_REDFLARE_1.yar#L4-L20"
		license_url = "https://github.com/mandiant/red_team_tool_countermeasures//blob/3561b71724dbfa3e2bb78106aaa2d7f8b892c43b/LICENSE.txt"
		hash = "79259451ff47b864d71fb3f94b1774f3, 82773afa0860d668d7fe40e3f22b0f3e"
		logic_hash = "282f11c4c86d88d05f11e92f5483701d9a54c2dd39f21316cd271aa78a338d0f"
		score = 75
		quality = 75
		tags = "FILE"
		rev = 1

	strings:
		$s1 = "find_applet_by_name" fullword
		$s2 = "bb_basename" fullword
		$s3 = "hk_printf_chk" fullword
		$s4 = "runCommand" fullword
		$s5 = "initialize" fullword

	condition:
		( uint32(0)==0x464c457f) and all of them
}