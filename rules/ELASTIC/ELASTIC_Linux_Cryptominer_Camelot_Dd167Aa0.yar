
rule ELASTIC_Linux_Cryptominer_Camelot_Dd167Aa0 : FILE MEMORY
{
	meta:
		description = "Detects Linux Cryptominer Camelot (Linux.Cryptominer.Camelot)"
		author = "Elastic Security"
		id = "dd167aa0-80e0-46dc-80d1-9ce9f6984860"
		date = "2021-01-12"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Cryptominer_Camelot.yar#L20-L37"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		logic_hash = "88be4fbb337fa866e126021b40a01d86a33029071af7efc289a8c5490d21ea8a"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "2642e4c4c58d95cd6ed6d38bf89b108dc978a865473af92494b6cb89f4f877e2"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { E7 F2 AE 4C 89 EF 48 F7 D1 48 89 CE 48 89 D1 F2 AE 48 89 C8 48 }

	condition:
		all of them
}