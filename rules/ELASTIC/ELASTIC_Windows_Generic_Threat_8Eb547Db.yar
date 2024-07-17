rule ELASTIC_Windows_Generic_Threat_8Eb547Db : FILE MEMORY
{
	meta:
		description = "Detects Windows Generic Threat (Windows.Generic.Threat)"
		author = "Elastic Security"
		id = "8eb547db-81e4-4c64-9bab-b7944af32345"
		date = "2024-01-17"
		modified = "2024-02-08"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Generic_Threat.yar#L1444-L1462"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "3fc821b63dfa653b86b11201073997fa4dc273124d050c2a7c267ac789d8a447"
		logic_hash = "73cabad0656c6b347def017b07138fdbdd5b41da5ccf7d701fea764669058f39"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "2de0d43a4c1c4b3ecef7272d3f224bd5203c130365ff49a02a9200b3f53fe6ba"
		severity = 50
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a1 = { 28 00 00 0A 20 B8 0B 00 00 20 10 27 00 00 6F 29 00 00 0A 28 1F 00 00 0A 7E 0D 00 00 04 2D 0A 28 23 00 00 06 28 19 00 00 06 7E 14 00 00 04 6F 2A 00 00 0A 26 17 2D C8 2A 13 30 01 00 41 00 00 00 }

	condition:
		all of them
}