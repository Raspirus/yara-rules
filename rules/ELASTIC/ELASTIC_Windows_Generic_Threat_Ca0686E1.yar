rule ELASTIC_Windows_Generic_Threat_Ca0686E1 : FILE MEMORY
{
	meta:
		description = "Detects Windows Generic Threat (Windows.Generic.Threat)"
		author = "Elastic Security"
		id = "ca0686e1-001f-44d2-ae2f-51c473769723"
		date = "2024-01-05"
		modified = "2024-01-12"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Generic_Threat.yar#L609-L627"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "15c7ce1bc55549efc86dea74a90f42fb4665fe15b14f760037897c772159a5b5"
		logic_hash = "12b2ff66d1be6e2d27f24489b389b5c84660921e8de41653b2b425077cc87669"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "4663eefedb6f3f502adfb4f64278d1c535ba3a719d007a280e9943914121cd81"
		severity = 50
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a1 = { 55 8B EC 51 53 8B 5D 08 56 57 8B F9 8B 77 10 8B C6 2B C3 89 75 FC 3B 45 0C 72 03 8B 45 0C 83 7F 14 10 72 02 8B 0F 8D 14 19 2B F0 8B CE 03 C2 2B CB 41 51 50 52 E8 62 1A 00 00 83 C4 0C 8B CF 56 }

	condition:
		all of them
}