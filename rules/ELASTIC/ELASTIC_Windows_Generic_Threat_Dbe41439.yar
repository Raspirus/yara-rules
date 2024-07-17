
rule ELASTIC_Windows_Generic_Threat_Dbe41439 : FILE MEMORY
{
	meta:
		description = "Detects Windows Generic Threat (Windows.Generic.Threat)"
		author = "Elastic Security"
		id = "dbe41439-982d-4897-9007-9ad0f206dc75"
		date = "2024-01-21"
		modified = "2024-02-08"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Generic_Threat.yar#L1749-L1767"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "64afd2bc6cec17402473a29b94325ae2e26989caf5a8b916dc21952149d71b00"
		logic_hash = "288cdc285d024f2b69847e0d49bd4dc1c86a2a6a24a7b4fb248071855ba39a38"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "f7c94f5bc3897c4741899e4f6d2731cd07f61e593500efdd33b5d84693465dd3"
		severity = 50
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a1 = { 83 E4 F8 83 EC 2C 53 56 8B F1 57 89 74 24 10 8B 46 1C 8B 08 85 C9 74 23 8B 56 2C 8B 3A 8D 04 0F 3B C8 73 17 8D 47 FF 89 02 8B 4E 1C 8B 11 8D 42 01 89 01 0F B6 02 E9 F1 00 00 00 33 DB }

	condition:
		all of them
}