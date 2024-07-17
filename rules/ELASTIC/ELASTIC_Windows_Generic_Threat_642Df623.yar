rule ELASTIC_Windows_Generic_Threat_642Df623 : FILE MEMORY
{
	meta:
		description = "Detects Windows Generic Threat (Windows.Generic.Threat)"
		author = "Elastic Security"
		id = "642df623-00ae-48a9-8d61-aaa688606807"
		date = "2024-02-20"
		modified = "2024-06-12"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Generic_Threat.yar#L2680-L2698"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "e5ba85d1a6a54df38b5fa655703c3457783f4a4f71e178f83d8aac878d4847da"
		logic_hash = "555eb66f117312fa4ff3a49c0c40f89caddec3eb4b93d11bda2cce40529d46a0"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "fb2c74f7e3e7f4e25173c375fe863e643183da4f5d718d61fdd0271fcc581deb"
		severity = 50
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a1 = { 55 8B EC 50 B8 04 00 00 00 81 C4 04 F0 FF FF 50 48 75 F6 8B 45 FC 81 C4 3C FE FF FF 53 56 57 64 8B 05 30 00 00 00 8B 40 0C 8B 40 0C 8B 00 8B 00 8B 40 18 89 45 FC 33 C9 8B 45 FC 89 45 DC 8B 45 }

	condition:
		all of them
}