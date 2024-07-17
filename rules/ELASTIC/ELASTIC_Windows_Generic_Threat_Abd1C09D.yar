
rule ELASTIC_Windows_Generic_Threat_Abd1C09D : FILE MEMORY
{
	meta:
		description = "Detects Windows Generic Threat (Windows.Generic.Threat)"
		author = "Elastic Security"
		id = "abd1c09d-ec66-45ee-b435-302c736cc1f9"
		date = "2024-03-05"
		modified = "2024-06-12"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Generic_Threat.yar#L3204-L3222"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "3ff09d2352c2163465d8c86f94baa25ba85c35698a5e3fbc52bc95afc06b7e85"
		logic_hash = "80e6f317e5cd91cb3819e9251efc8c96218071bec577a38c8784826dd4a657cb"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "2f75d8fa11f67f983e40ada50a07e8a6f1b6dfc663524e35a6526381e939d39f"
		severity = 50
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a1 = { 83 EC 0C 8B D1 53 56 57 8B 7D 0C 83 FF 08 77 1A 85 FF 74 16 8B 5D 08 8B 4A 14 8B 72 10 2B CE 8D 04 3B 3B C1 72 11 C6 42 44 00 33 C0 33 D2 5F 5E 5B 8B E5 5D C2 08 00 0F 57 C0 66 0F 13 }

	condition:
		all of them
}