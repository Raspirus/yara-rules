rule ELASTIC_Windows_Generic_Threat_54A914C9 : FILE MEMORY
{
	meta:
		description = "Detects Windows Generic Threat (Windows.Generic.Threat)"
		author = "Elastic Security"
		id = "54a914c9-1b00-4cea-9b82-f7ed1df1305f"
		date = "2024-03-25"
		modified = "2024-06-12"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Generic_Threat.yar#L3304-L3322"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "c418c5ad8030985bb5067cda61caba3b7a0d24cb8d3f93fc09d452fbdf4174ec"
		logic_hash = "0cc3797564b4c722423f915493e07b0e0fec3085e7a535f9914f82d73c797bed"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "d3f4083c96130031ce9656ea31bf0914080c88f09c05f8b1168c60487af80c9b"
		severity = 50
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a1 = { 20 48 89 CB 48 8B 43 08 4C 8B 48 30 4D 85 C9 74 16 48 8D 4B 10 0F B6 D2 48 83 C4 20 5B 5E 5F 5D 41 5C 49 FF E1 66 90 44 0F B6 40 10 41 80 F8 16 0F 84 81 00 00 00 41 80 F8 18 74 0B 48 }

	condition:
		all of them
}