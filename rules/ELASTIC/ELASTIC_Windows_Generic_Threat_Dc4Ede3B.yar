rule ELASTIC_Windows_Generic_Threat_Dc4Ede3B : FILE MEMORY
{
	meta:
		description = "Detects Windows Generic Threat (Windows.Generic.Threat)"
		author = "Elastic Security"
		id = "dc4ede3b-d0c7-4993-8629-88753d65a7ad"
		date = "2024-01-21"
		modified = "2024-02-08"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Generic_Threat.yar#L1871-L1889"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "c49f20c5b42c6d813e6364b1fcb68c1b63a2f7def85a3ddfc4e664c4e90f8798"
		logic_hash = "c402d5f16f2be32912d7a054b51ab6dafc6173bb5a267a7846b3ac9df1c4c19f"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "8be5afdf2a5fe5cb1d4b50d10e8e2e8e588a72d6c644aa1013dd293c484da33b"
		severity = 50
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a1 = { 55 89 E5 83 EC 28 C7 45 FC 00 00 00 00 C7 44 24 18 00 00 00 00 C7 44 24 14 00 00 00 00 C7 44 24 10 03 00 00 00 C7 44 24 0C 00 00 00 00 C7 44 24 08 00 00 00 00 C7 44 24 04 00 00 00 80 8B 45 08 }

	condition:
		all of them
}