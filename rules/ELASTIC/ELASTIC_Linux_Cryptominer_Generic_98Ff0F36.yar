
rule ELASTIC_Linux_Cryptominer_Generic_98Ff0F36 : FILE MEMORY
{
	meta:
		description = "Detects Linux Cryptominer Generic (Linux.Cryptominer.Generic)"
		author = "Elastic Security"
		id = "98ff0f36-5faf-417a-9431-8a44e9f088f4"
		date = "2021-01-12"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Cryptominer_Generic.yar#L261-L279"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "4c14aaf05149bb38bbff041432bf9574dd38e851038638aeb121b464a1e60dcc"
		logic_hash = "60f17855b08cfc51e497003cbb5ed25d9168fb29c57d8bfd7105b9b5e714e3a1"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "b25420dfc32522a060dc8470315409280e3c03de0b347e92a5bc6c1a921af94a"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { 45 A8 8B 00 89 C2 48 8B 45 C8 48 01 C2 8B 45 90 48 39 C2 7E 08 8B }

	condition:
		all of them
}