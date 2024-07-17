
rule ELASTIC_Windows_Generic_Threat_Bb480769 : FILE MEMORY
{
	meta:
		description = "Detects Windows Generic Threat (Windows.Generic.Threat)"
		author = "Elastic Security"
		id = "bb480769-57fb-4c93-8330-450f563fd4c6"
		date = "2024-01-21"
		modified = "2024-02-08"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Generic_Threat.yar#L1891-L1909"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "010e3aeb26533d418bb7d2fdcfb5ec21b36603b6abb63511be25a37f99635bce"
		logic_hash = "1087e0befceac2606ce5dc5f2b42b45ebad888e7d3e451c3fb89de7e932a31f5"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "9c58c2e028f99737574d49e47feb829058f6082414b58d6c9e569a50904591e7"
		severity = 50
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a1 = { 55 89 E5 C6 45 03 B8 C7 45 08 BA EF BE AD C7 45 0C DE 89 10 BA C7 45 10 EF BE AD DE C7 45 14 89 50 04 B8 C7 45 18 EF BE AD DE C7 45 1C 6A 00 6A 01 C7 45 20 6A 00 FF D0 C7 45 24 B8 EF BE AD C7 }

	condition:
		all of them
}