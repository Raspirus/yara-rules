
rule ELASTIC_Windows_Generic_Threat_Acf6222B : FILE MEMORY
{
	meta:
		description = "Detects Windows Generic Threat (Windows.Generic.Threat)"
		author = "Elastic Security"
		id = "acf6222b-5859-4b18-a770-04f8fc7f48fd"
		date = "2024-01-03"
		modified = "2024-01-12"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Generic_Threat.yar#L510-L528"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "ce0def96be08193ab96817ce1279e8406746a76cfcf4bf44e394920d7acbcaa6"
		logic_hash = "a284b6c163dbc022bd36f19fbc1d7ff70143bee566328ad23e7b8b79abd39e91"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "1046de07f9594a6352a33d892da1b4dc227fdf52a8caf38e8f1532076232c7fc"
		severity = 50
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a1 = { 83 7D 10 00 75 04 33 C0 5D C3 8B 4D 08 8B 55 0C FF 4D 10 74 0E 8A 01 84 C0 74 08 3A 02 75 04 41 42 EB ED 0F B6 01 0F B6 0A 2B C1 5D C3 55 8B EC 83 EC 24 56 57 8B 7D 08 33 F6 89 75 F8 }

	condition:
		all of them
}