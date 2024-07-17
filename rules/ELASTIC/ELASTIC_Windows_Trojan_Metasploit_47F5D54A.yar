
rule ELASTIC_Windows_Trojan_Metasploit_47F5D54A : FILE MEMORY
{
	meta:
		description = "Detects Windows Trojan Metasploit (Windows.Trojan.Metasploit)"
		author = "Elastic Security"
		id = "47f5d54a-2578-4bbd-b157-8b225f6d34b3"
		date = "2023-11-13"
		modified = "2024-01-12"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Trojan_Metasploit.yar#L353-L372"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "bc3754cf4a04491a7ad7a75f69dd3bb2ddf0d8592ce078b740d7c9c7bc85a7e1"
		logic_hash = "be080d0aae457348c4a02c204507a8cb14d1728d1bc50d7cf12b577aa06daf9f"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "b6dbc1b273bc9a328d5c437d11db23e8f1d3bf764bb624aa4f552c14b3dc5260"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a32 = { 89 45 F8 FF 15 [11] 8B D8 85 DB 74 76 6A 00 6A 04 6A 00 FF 35 [4] 6A 00 6A 00 FF 15 }
		$a64 = { 48 89 7C 24 48 FF 15 [4] 33 D2 44 8B C0 B9 40 00 10 00 FF 15 [4] 48 8B F8 48 85 C0 74 55 48 8B 15 [10] 4C 8B C0 48 8B CB 48 C7 44 24 20 }

	condition:
		any of them
}