
rule FIREEYE_RT_Hacktool_MSIL_Puppyhound_1 : FILE
{
	meta:
		description = "This is a modification of an existing FireEye detection for SharpHound. However, it looks for the string 'PuppyHound' instead of 'SharpHound' as this is all that was needed to detect the PuppyHound variant of SharpHound."
		author = "FireEye"
		id = "1155f959-c8bc-597a-8a80-abee8d95b6ec"
		date = "2020-12-09"
		modified = "2020-12-09"
		reference = "https://github.com/mandiant/red_team_tool_countermeasures/"
		source_url = "https://github.com/mandiant/red_team_tool_countermeasures//blob/3561b71724dbfa3e2bb78106aaa2d7f8b892c43b/rules/PUPPYHOUND/production/yara/HackTool_MSIL_PuppyHound_1.yar#L4-L19"
		license_url = "https://github.com/mandiant/red_team_tool_countermeasures//blob/3561b71724dbfa3e2bb78106aaa2d7f8b892c43b/LICENSE.txt"
		hash = "eeedc09570324767a3de8205f66a5295"
		logic_hash = "39073bbfef15ecd28c1772e5d01e54c3d5774ecb4c90f0076bda5dc400abacba"
		score = 75
		quality = 75
		tags = "FILE"
		rev = 6

	strings:
		$1 = "PuppyHound"
		$2 = "UserDomainKey"
		$3 = "LdapBuilder"
		$init = { 28 [2] 00 0A 0A 72 [2] 00 70 1? ?? 28 [2] 00 0A 72 [2] 00 70 1? ?? 28 [2] 00 0A 28 [2] 00 0A 0B 1F 2D }
		$msil = /\x00_Cor(Exe|Dll)Main\x00/

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and all of them
}