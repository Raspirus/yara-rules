
rule ELASTIC_Windows_Generic_Threat_6542Ebda : FILE MEMORY
{
	meta:
		description = "Detects Windows Generic Threat (Windows.Generic.Threat)"
		author = "Elastic Security"
		id = "6542ebda-c91e-449e-88c4-244fba69a4b2"
		date = "2024-01-17"
		modified = "2024-02-08"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Generic_Threat.yar#L1546-L1564"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "2073e51c7db7040c6046e36585873a0addc2bcddeb6e944b46f96c607dd83595"
		logic_hash = "30263341bf51a001503dfda9be5771d401bc5b5423682c29a6d4ebc457415d3e"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "a4ceaf0bf2e8dc3efbc6e41e608816385f40c04984659b0ec15f109b7a6bf20a"
		severity = 50
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a1 = { 55 8B EC 53 56 57 8B F9 85 D2 74 18 0F B7 02 8D 5A 02 0F B7 72 02 8B 4A 04 3B C7 74 0E 83 C2 08 03 D1 75 E8 33 C0 5F 5E 5B 5D C3 B8 78 03 00 00 66 3B F0 74 EF 8B 45 08 89 18 8D 41 06 EB E7 8D }

	condition:
		all of them
}