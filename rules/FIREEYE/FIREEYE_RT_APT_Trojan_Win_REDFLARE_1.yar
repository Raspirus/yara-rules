
rule FIREEYE_RT_APT_Trojan_Win_REDFLARE_1 : FILE
{
	meta:
		description = "No description has been set in the source file - FireEye-RT"
		author = "FireEye"
		id = "c3054680-9c87-5d90-b78e-b260904340df"
		date = "2020-11-27"
		date = "2020-11-27"
		modified = "2020-12-09"
		reference = "https://github.com/mandiant/red_team_tool_countermeasures/"
		source_url = "https://github.com/mandiant/red_team_tool_countermeasures//blob/3561b71724dbfa3e2bb78106aaa2d7f8b892c43b/rules/REDFLARE/production/yara/APT_Trojan_Win_REDFLARE_1.yar#L4-L21"
		license_url = "https://github.com/mandiant/red_team_tool_countermeasures//blob/3561b71724dbfa3e2bb78106aaa2d7f8b892c43b/LICENSE.txt"
		hash = "100d73b35f23b2fe84bf7cd37140bf4d,4e7e90c7147ee8aa01275894734f4492"
		logic_hash = "08ea2151418f7f75a8b138146c393a5ea85647320cc8e9fe1930d75871ab94bb"
		score = 75
		quality = 75
		tags = "FILE"
		rev = 3

	strings:
		$1 = "initialize" fullword
		$2 = "runCommand" fullword
		$3 = "stop" fullword
		$4 = "fini" fullword
		$5 = "VirtualAllocEx" fullword
		$6 = "WriteProcessMemory" fullword

	condition:
		( uint16(0)==0x5A4D) and ( uint32( uint32(0x3C))==0x00004550) and all of them
}