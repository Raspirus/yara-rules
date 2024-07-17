
rule ELASTIC_Windows_Trojan_Trickbot_1E56Fad7 : FILE MEMORY
{
	meta:
		description = "Detects Windows Trojan Trickbot (Windows.Trojan.Trickbot)"
		author = "Elastic Security"
		id = "1e56fad7-383f-4ee0-9f8f-a0b3dcceb691"
		date = "2021-03-28"
		modified = "2021-08-23"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Trojan_Trickbot.yar#L60-L77"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		logic_hash = "815b37804f79fb4607e6b84294882d818233c3df13aececb3d341244900a2e44"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "a0916134f47df384bbdacff994970f60d3613baa03c0a581b7d1dd476af3121b"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a = { 5B C9 C2 18 00 43 C1 02 10 7C C2 02 10 54 C1 02 10 67 C1 02 10 }

	condition:
		all of them
}