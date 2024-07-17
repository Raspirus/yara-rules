
rule ELASTIC_Windows_Trojan_Trickbot_B17B33A1 : FILE MEMORY
{
	meta:
		description = "Detects Windows Trojan Trickbot (Windows.Trojan.Trickbot)"
		author = "Elastic Security"
		id = "b17b33a1-1021-4980-8ffd-2e7aa4ca2ae4"
		date = "2021-03-28"
		modified = "2021-08-23"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Trojan_Trickbot.yar#L345-L362"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		logic_hash = "7fa69674d1e985bafe310597f23ae80113136768141f0a1931baf88b2509e6ef"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "753d15c1ff0cc4cf75250761360bb35280ff0a1a4d34320df354e0329dd35211"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a = { 08 53 55 56 57 64 A1 30 00 00 00 89 44 24 10 8B 44 24 10 8B }

	condition:
		all of them
}