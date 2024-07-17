import "pe"


import "pe"


rule FIREEYE_RT_APT_Loader_Win32_Dshell_2 : FILE
{
	meta:
		description = "No description has been set in the source file - FireEye-RT"
		author = "FireEye"
		id = "ae34d547-d979-5ce2-bcf8-a5b4e4567de3"
		date = "2020-11-27"
		date = "2020-11-27"
		modified = "2020-12-09"
		reference = "https://github.com/mandiant/red_team_tool_countermeasures/"
		source_url = "https://github.com/mandiant/red_team_tool_countermeasures//blob/3561b71724dbfa3e2bb78106aaa2d7f8b892c43b/rules/DSHELL/production/yara/APT_Loader_Win32_DShell_2.yar#L4-L21"
		license_url = "https://github.com/mandiant/red_team_tool_countermeasures//blob/3561b71724dbfa3e2bb78106aaa2d7f8b892c43b/LICENSE.txt"
		hash = "590d98bb74879b52b97d8a158af912af"
		logic_hash = "958ff45add46c0a43e839e8007c1d9296ee89ddd8c045b8ec6b031b225207a6c"
		score = 75
		quality = 75
		tags = "FILE"
		rev = 2

	strings:
		$sb1 = { 6A 40 68 00 30 00 00 [4-32] E8 [4-8] 50 [0-16] E8 [4-150] 6A FF [1-32] 6A 00 6A 00 5? 6A 00 6A 00 [0-32] E8 [4] 50 }
		$ss1 = "\x00CreateThread\x00"
		$ss2 = "base64.d" fullword
		$ss3 = "core.sys.windows" fullword
		$ss4 = "C:\\Users\\config.ini" fullword
		$ss5 = "Invalid config file" fullword

	condition:
		( uint16(0)==0x5A4D) and ( uint32( uint32(0x3C))==0x00004550) and ( uint16( uint32(0x3C)+0x18)==0x010B) and all of them
}