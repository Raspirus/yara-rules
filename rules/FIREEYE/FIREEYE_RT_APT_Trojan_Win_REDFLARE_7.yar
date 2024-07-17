rule FIREEYE_RT_APT_Trojan_Win_REDFLARE_7 : FILE
{
	meta:
		description = "No description has been set in the source file - FireEye-RT"
		author = "FireEye"
		id = "f891e477-9ff2-57be-9ca5-dd87d9baee29"
		date = "2020-12-02"
		date = "2020-12-02"
		modified = "2020-12-09"
		reference = "https://github.com/mandiant/red_team_tool_countermeasures/"
		source_url = "https://github.com/mandiant/red_team_tool_countermeasures//blob/3561b71724dbfa3e2bb78106aaa2d7f8b892c43b/rules/REDFLARE/production/yara/APT_Trojan_Win_REDFLARE_7.yar#L4-L21"
		license_url = "https://github.com/mandiant/red_team_tool_countermeasures//blob/3561b71724dbfa3e2bb78106aaa2d7f8b892c43b/LICENSE.txt"
		hash = "e7beece34bdf67cbb8297833c5953669, 8025bcbe3cc81fc19021ad0fbc11cf9b"
		logic_hash = "6d7822256ac1bef05304d3396df773e2b20a397311ad820d6ec5fe4cb6bdfbbc"
		score = 75
		quality = 75
		tags = "FILE"
		rev = 1

	strings:
		$1 = "initialize" fullword
		$2 = "getData" fullword
		$3 = "putData" fullword
		$4 = "fini" fullword
		$5 = "NamedPipe"
		$named_pipe = { 88 13 00 00 [1-8] E8 03 00 00 [20-60] 00 00 00 00 [1-8] 00 00 00 00 [1-40] ( 6A 00 6A 00 6A 03 6A 00 6A 00 68 | 00 00 00 00 [1-6] 00 00 00 00 [1-6] 03 00 00 00 45 33 C? 45 33 C? BA ) 00 00 00 C0 [2-10] FF 15 [4-30] FF 15 [4-7] E7 00 00 00 [4-40] FF 15 [4] 85 C0 }

	condition:
		( uint16(0)==0x5A4D) and ( uint32( uint32(0x3C))==0x00004550) and all of them
}