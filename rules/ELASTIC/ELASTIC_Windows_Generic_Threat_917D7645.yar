rule ELASTIC_Windows_Generic_Threat_917D7645 : FILE MEMORY
{
	meta:
		description = "Detects Windows Generic Threat (Windows.Generic.Threat)"
		author = "Elastic Security"
		id = "917d7645-f13e-4d66-ab9e-447a19923ab7"
		date = "2024-01-21"
		modified = "2024-02-08"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Generic_Threat.yar#L1831-L1849"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "19b54a20cfa74cbb0f4724155244b52ca854054a205be6d148f826fa008d6c55"
		logic_hash = "65748ff2e4448f305b9541ea9864cc6bda054d37be5ed34110a2f64c8fef30c7"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "557b459c07dc7d7e32cac389673d5ab487d1730de20a9ec74ae9432325d40cd2"
		severity = 50
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a1 = { 83 E4 E0 56 57 53 81 EC D4 0A 00 00 8B D9 8B F2 BA 1D 00 00 00 FF 73 1C 8D 8C 24 BC 0A 00 00 E8 19 A1 02 00 6A 00 FF B4 24 BC 0A 00 00 8D 8C 24 A8 0A 00 00 E8 D4 06 03 00 8D 8C 24 B8 }

	condition:
		all of them
}