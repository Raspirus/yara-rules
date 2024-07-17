
rule ELASTIC_Linux_Cryptominer_Uwamson_C42Fd06D : FILE MEMORY
{
	meta:
		description = "Detects Linux Cryptominer Uwamson (Linux.Cryptominer.Uwamson)"
		author = "Elastic Security"
		id = "c42fd06d-b9ab-4f1f-bb59-e7b49355115c"
		date = "2021-01-12"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Cryptominer_Uwamson.yar#L1-L19"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "8cfc38db2b860efcce5da40ce1e3992f467ab0b7491639d68d530b79529cda80"
		logic_hash = "4ff7aad11adaae8fccb23d36fc96937ba48a5517895a742f2864ba1973f3db3a"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "dac171e66289e2222cd631d616f31829f31dfeeffb34f0e1dcdd687d294f117c"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { F0 4C 89 F3 48 8B 34 24 48 C1 E0 04 48 C1 E3 07 48 8B 7C 24 10 48 }

	condition:
		all of them
}