
rule ELASTIC_Windows_Backdoor_Dragoncastling_4Ecf6F9F : FILE MEMORY
{
	meta:
		description = "Detects Windows Backdoor Dragoncastling (Windows.Backdoor.DragonCastling)"
		author = "Elastic Security"
		id = "4ecf6f9f-a4c8-4962-9f16-cf7fb76467d3"
		date = "2022-11-08"
		modified = "2022-12-20"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Backdoor_DragonCastling.yar#L1-L27"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "9776c7ae6ca73f87d7c838257a5bcd946372fbb77ebed42eebdfb633b13cd387"
		logic_hash = "26ff86354230f1006bd451eab5c1634b91888330d124a06dd2dfa5ab515d6e1a"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "be22acb2c9c28b68d9fffe255f7d72065fb683ef2e3c4f73914f51e14ae43175"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a1 = "recv bomb" ascii fullword
		$a2 = "%s\\kbg%x.dat"
		$a3 = "\\smcache.dat" wide fullword
		$a4 = "%s\\game_%x.log"
		$a5 = "{%08X-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X}"
		$a7 = "HOST: %ws:%ws" ascii fullword
		$a8 = "; Windows NT %d.%d" wide fullword
		$a9 = "Mozilla / 5.0 (Windows NT 6.3; WOW64) AppleWebKit / 537.36 (KHTML, like Gecko) Chrome / 41.0.2272.118 Safari / 537.36" ascii fullword
		$a10 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\\User Agent\\Post Platform" wide fullword

	condition:
		5 of them
}