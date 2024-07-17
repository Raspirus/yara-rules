
rule ELASTIC_Linux_Trojan_Mirai_24C5B7D6 : FILE MEMORY
{
	meta:
		description = "Detects Linux Trojan Mirai (Linux.Trojan.Mirai)"
		author = "Elastic Security"
		id = "24c5b7d6-1aa8-4d8e-9983-c7234f57c3de"
		date = "2021-01-12"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Trojan_Mirai.yar#L478-L496"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "7c2f8ba2d6f1e67d1b4a3a737a449429c322d945d49dafb9e8c66608ab2154c4"
		logic_hash = "f790f6b8fcf932773054525ed74a3f15998d91a2626ae9c56486de8dabc2035c"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "3411b624f02dd1c7a0e663f1f119c8d5e47a81892bb7c445b7695c605b0b8ee2"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { 54 38 1C 80 FA 3E 74 25 80 FA 3A 74 20 80 FA 24 74 1B 80 FA 23 }

	condition:
		all of them
}