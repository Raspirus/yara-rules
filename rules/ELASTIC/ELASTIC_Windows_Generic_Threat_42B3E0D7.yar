rule ELASTIC_Windows_Generic_Threat_42B3E0D7 : FILE MEMORY
{
	meta:
		description = "Detects Windows Generic Threat (Windows.Generic.Threat)"
		author = "Elastic Security"
		id = "42b3e0d7-ec42-4940-b5f3-e9782997dccf"
		date = "2024-01-17"
		modified = "2024-02-08"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Generic_Threat.yar#L1240-L1258"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "99ad416b155970fda383a63fe61de2e4d0254e9c9e09564e17938e8e2b49b5b7"
		logic_hash = "58b4c667b6d796f4525afeb706394f593d03393e3a48e2a0b7664f121e6a78fe"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "7d3974400d05bc7bbcd63c99e8257d0676b38335de74a4bcfde9e86553f50f08"
		severity = 50
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a1 = { 83 C4 F8 53 33 DB 6A 00 8D 45 F8 50 8B 45 0C 50 8B 45 10 50 6A 00 6A 00 33 C9 33 D2 8B 45 08 E8 B1 F7 FF FF 85 C0 75 05 BB 01 00 00 00 8B C3 5B 59 59 5D C2 0C 00 8D 40 00 53 BB E0 E1 }

	condition:
		all of them
}