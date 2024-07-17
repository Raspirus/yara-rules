rule ELASTIC_Windows_Generic_Threat_6Ee18020 : FILE MEMORY
{
	meta:
		description = "Detects Windows Generic Threat (Windows.Generic.Threat)"
		author = "Elastic Security"
		id = "6ee18020-71e2-4003-99ef-963663e94740"
		date = "2024-01-17"
		modified = "2024-02-08"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Generic_Threat.yar#L1424-L1442"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "d58d8f5a7efcb02adac92362d8c608e6d056824641283497b2e1c1f0e2d19b0a"
		logic_hash = "8a08973ae2ddde275e007686fc6eca831c1fb398b7221d5022da10f90da0e44d"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "b8b18dcec6556bc7fb9b9f257a6485bcd6dfde96fc5c7e8145664de55d0c6803"
		severity = 50
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a1 = { 55 8B EC 53 8B 5D 0C 8B 45 08 50 E8 9C 19 02 00 59 89 03 89 53 04 83 7B 04 00 75 07 83 3B 00 76 10 EB 02 7E 0C C6 43 28 01 33 C0 5B 5D C3 5B 5D C3 B8 01 00 00 00 5B 5D C3 90 90 90 55 8B EC 53 }

	condition:
		all of them
}