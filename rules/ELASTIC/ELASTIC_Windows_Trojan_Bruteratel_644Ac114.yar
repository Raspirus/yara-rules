
rule ELASTIC_Windows_Trojan_Bruteratel_644Ac114 : FILE MEMORY
{
	meta:
		description = "Detects Windows Trojan Bruteratel (Windows.Trojan.BruteRatel)"
		author = "Elastic Security"
		id = "644ac114-cc66-443e-9dd0-a591be99a86c"
		date = "2024-04-17"
		modified = "2024-05-08"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Trojan_BruteRatel.yar#L186-L205"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "ace6a99d95ef859d4ab74db6900753e754273a12a34721f1aa8f1a9df3d8ec35"
		logic_hash = "06ffea16a0348f2276f379db150b5f9d2dbdffbcb2eee83c55c27c837ecb1e69"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "471b2e5f0ae2a08accb90c602af5e892afc1f2a140b25db977df610123cf60be"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a = { 80 39 0F 75 ?? 80 79 01 05 75 ?? 80 79 02 C3 75 ?? 48 89 C8 C3 }
		$b = { 80 79 01 8B 75 ?? 80 79 02 D1 75 ?? 41 80 F9 B8 75 ?? 80 79 06 00 75 ?? 0F B6 41 05 C1 E0 08 41 89 C0 0F B6 41 04 }

	condition:
		all of them
}