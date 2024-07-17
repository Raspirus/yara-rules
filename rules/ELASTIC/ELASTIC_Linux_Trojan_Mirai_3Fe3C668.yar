rule ELASTIC_Linux_Trojan_Mirai_3Fe3C668 : FILE MEMORY
{
	meta:
		description = "Detects Linux Trojan Mirai (Linux.Trojan.Mirai)"
		author = "Elastic Security"
		id = "3fe3c668-89f4-4601-a167-f41bbd984ae5"
		date = "2021-01-12"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Trojan_Mirai.yar#L518-L535"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		logic_hash = "e75b2dca7de7d9f31a0ae5940dc45d0e6d0f1ca110b5458fc99912400da97bde"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "2a79caea707eb0ecd740106ea4bed2918e7592c1e5ad6050f6f0992cf31ba5ec"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { 00 84 C0 0F 95 C0 48 FF 45 E8 84 C0 75 E9 8B 45 FC C9 C3 55 48 }

	condition:
		all of them
}