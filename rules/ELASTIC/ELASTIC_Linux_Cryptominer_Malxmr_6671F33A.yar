
rule ELASTIC_Linux_Cryptominer_Malxmr_6671F33A : FILE MEMORY
{
	meta:
		description = "Detects Linux Cryptominer Malxmr (Linux.Cryptominer.Malxmr)"
		author = "Elastic Security"
		id = "6671f33a-03bb-40d8-b439-64a66082457d"
		date = "2021-01-12"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Cryptominer_Malxmr.yar#L141-L159"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "85fa30ba59602199fd99463acf50bd607e755c2e18cd8843ffcfb6b1aca24bb3"
		logic_hash = "a15c842c7c7ec3b11183a1502f8ec03ea786e3f0d47fbab58c62ffff7b018030"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "cb178050ee351059b083c6a71b5b1b6a9e0aa733598a05b3571701949b4e6b28"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { 4D 18 48 01 4B 18 5A 5B 5D C3 83 C8 FF C3 48 85 FF 49 89 F8 }

	condition:
		all of them
}