rule ELASTIC_Windows_Trojan_Trickbot_F8Dac4Bc : FILE MEMORY
{
	meta:
		description = "Targets rdpscan module used to bruteforce RDP"
		author = "Elastic Security"
		id = "f8dac4bc-2ea1-4733-a260-59f3cae2eba8"
		date = "2021-03-30"
		modified = "2021-08-23"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Trojan_Trickbot.yar#L923-L954"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "13d102d546b9384f944f2a520ba32fb5606182bed45a8bba681e4374d7e5e322"
		logic_hash = "d4536aac0ee402abcb87826e45c892d6f39562bc1e39b72ae8880dc077f230d9"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "256daf823f6296ae02103336817dec565129a11f37445b791b2f8e3163f0c17f"
		threat_name = "Windows.Trojan.Trickbot"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a1 = "rdpscan.dll" ascii fullword
		$a2 = "F:\\rdpscan\\Bin\\Release_nologs\\"
		$a3 = "Cookie: %s %s" wide fullword
		$a4 = "<moduleconfig><needinfo name=\"id\"/><needinfo name=\"ip\"/><autoconf><conf ctl=\"srv\" file=\"srv\" period=\"60\"/></autoconf><"
		$a5 = "<moduleconfig><needinfo name=\"id\"/><needinfo name=\"ip\"/><autoconf><conf ctl=\"srv\" file=\"srv\" period=\"60\"/></autoconf><"
		$a6 = "X^Failed to create a list of contr" ascii fullword
		$a7 = "rdp/domains" wide fullword
		$a8 = "Your product name" wide fullword
		$a9 = "rdp/over" wide fullword
		$a10 = "rdp/freq" wide fullword
		$a11 = "rdp/names" wide fullword
		$a12 = "rdp/dict" wide fullword
		$a13 = "rdp/mode" wide fullword

	condition:
		4 of ($a*)
}