rule ELASTIC_Windows_Trojan_Trickbot_997B25A0 : FILE MEMORY
{
	meta:
		description = "Detects Windows Trojan Trickbot (Windows.Trojan.Trickbot)"
		author = "Elastic Security"
		id = "997b25a0-aeac-4f74-aa87-232c4f8329b6"
		date = "2021-03-28"
		modified = "2021-08-23"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Trojan_Trickbot.yar#L326-L343"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		logic_hash = "ca688086c4628c64c32a99083d620bcb5373e3100d154331451a3e9f86081aca"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "0bba1c5284ed0548f51fdfd6fb96e24f92f7f4132caefbf0704efb0b1a64b7c4"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a = { 85 D2 74 F0 C6 45 E1 20 8D 4D E1 C6 45 E2 4A C6 45 E3 4A C6 45 }

	condition:
		all of them
}