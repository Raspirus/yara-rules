rule FIREEYE_RT_APT_Loader_Win32_Dshell_1 : FILE
{
	meta:
		description = "No description has been set in the source file - FireEye-RT"
		author = "FireEye"
		id = "dad763bd-0e4a-542a-9920-ece11d23ce24"
		date = "2020-11-27"
		date = "2020-11-27"
		modified = "2020-12-09"
		reference = "https://github.com/mandiant/red_team_tool_countermeasures/"
		source_url = "https://github.com/mandiant/red_team_tool_countermeasures//blob/3561b71724dbfa3e2bb78106aaa2d7f8b892c43b/rules/DSHELL/production/yara/APT_Loader_Win32_DShell_1.yar#L4-L20"
		license_url = "https://github.com/mandiant/red_team_tool_countermeasures//blob/3561b71724dbfa3e2bb78106aaa2d7f8b892c43b/LICENSE.txt"
		hash = "12c3566761495b8353f67298f15b882c"
		logic_hash = "79643f9c252765647d80f6fe1ee7bb698fbc6a6c3a0ff1fd819a09bff031907c"
		score = 75
		quality = 75
		tags = "FILE"
		rev = 1

	strings:
		$sb1 = { 6A 40 68 00 30 00 00 [4-32] E8 [4-8] 50 [0-16] E8 [4-150] 6A FF [1-32] 6A 00 6A 00 5? 6A 00 6A 00 [0-32] E8 [4] 50 }
		$sb2 = { FF 7? 0C B? [4-16] FF 7? 08 5? [0-12] E8 [4] 84 C0 74 05 B? 01 00 00 00 [0-16] 80 F2 01 0F 84 }
		$ss1 = "\x00CreateThread\x00"
		$ss2 = "base64.d" fullword
		$ss3 = "core.sys.windows" fullword

	condition:
		( uint16(0)==0x5A4D) and ( uint32( uint32(0x3C))==0x00004550) and ( uint16( uint32(0x3C)+0x18)==0x010B) and all of them
}