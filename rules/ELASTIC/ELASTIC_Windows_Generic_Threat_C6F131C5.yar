rule ELASTIC_Windows_Generic_Threat_C6F131C5 : FILE MEMORY
{
	meta:
		description = "Detects Windows Generic Threat (Windows.Generic.Threat)"
		author = "Elastic Security"
		id = "c6f131c5-8737-4f48-a0fe-a94e9565481e"
		date = "2024-01-12"
		modified = "2024-02-08"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Generic_Threat.yar#L1055-L1073"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "247314baaaa993b8db9de7ef0e2998030f13b99d6fd0e17ffd59e31a8d17747a"
		logic_hash = "5702a77fee0cd564916abdbfedf76d069bb7a5b6de0c4623150991d52dc02e42"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "c4349bd78cdc64430d15caf7efd663ff88d79d69ecf9f8118122b9a85543057d"
		severity = 50
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a1 = { 20 48 8B 59 08 8B 13 44 8B 43 04 48 83 C3 08 89 D0 44 09 C0 74 07 E8 B6 FF FF FF EB E8 48 83 C4 20 5B C3 53 45 31 DB BB 0D 00 00 00 48 8B 41 10 45 89 DA 49 C1 E2 04 4A 83 3C 10 00 74 }

	condition:
		all of them
}