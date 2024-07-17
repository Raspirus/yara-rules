rule ELASTIC_Windows_Generic_Threat_E052D248 : FILE MEMORY
{
	meta:
		description = "Detects Windows Generic Threat (Windows.Generic.Threat)"
		author = "Elastic Security"
		id = "e052d248-32f2-4d51-b42d-468a09e06daa"
		date = "2023-12-18"
		modified = "2024-01-12"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Generic_Threat.yar#L82-L100"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "ed2bbc0d120665044aacb089d8c99d7c946b54d1b08a078aebbb3b91f593da6e"
		logic_hash = "1a16ce6d1c6707560425156e625ad19a82315564b3f03adafbcc3e65b0e98a6d"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "ccfbcb9271b1ce99b814cf9e3a4776e9501035166824beaf39d4b8cd03446ef3"
		severity = 50
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a1 = { 55 8B EC 64 A1 00 00 00 00 6A FF 68 4F 5A 54 00 50 64 89 25 00 00 00 00 6A 02 68 24 D0 58 00 E8 FF 65 10 00 C7 45 FC FF FF FF FF 68 10 52 55 00 E8 F7 72 10 00 8B 4D F4 83 C4 0C 64 89 0D 00 00 }

	condition:
		all of them
}