rule ELASTIC_Windows_Generic_Threat_Dbceec58 : FILE MEMORY
{
	meta:
		description = "Detects Windows Generic Threat (Windows.Generic.Threat)"
		author = "Elastic Security"
		id = "dbceec58-0b98-470c-8439-23aa26b4064f"
		date = "2024-02-20"
		modified = "2024-06-12"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Generic_Threat.yar#L2720-L2738"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "fbec30528e6f261aebf0d41f3cd6d35fcc937f1e20e1070f99b1b327f02b91e0"
		logic_hash = "2a99fb7b342b43e3a4f0136d7d618625ca5708ae32e6fcabb11420bd8c89915b"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "5f470a7367ebbffebae8384aa552b3e9b1bda6bf4a3241bda047970341ee7c4c"
		severity = 50
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a1 = { 83 EC 14 83 7D 08 00 74 0C 83 7D 0C 00 74 06 83 7D 10 00 75 08 8B 45 08 E9 87 00 00 00 8B 45 08 89 45 FC 8B 45 0C 89 45 F8 8B 45 10 C1 E8 02 89 45 EC 83 65 F4 00 EB 07 8B 45 F4 40 89 }

	condition:
		all of them
}