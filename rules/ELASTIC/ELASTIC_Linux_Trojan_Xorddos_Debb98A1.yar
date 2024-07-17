rule ELASTIC_Linux_Trojan_Xorddos_Debb98A1 : FILE MEMORY
{
	meta:
		description = "Detects Linux Trojan Xorddos (Linux.Trojan.Xorddos)"
		author = "Elastic Security"
		id = "debb98a1-c861-4458-8bff-fae4f00a17dc"
		date = "2022-09-12"
		modified = "2022-10-18"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Trojan_Xorddos.yar#L157-L175"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "494f549e3dd144e8bcb230dd7b3faa8ff5107d86d9548b21b619a0318e362cad"
		logic_hash = "c2e43818fcf18d34a6a3611aaaafde31d96b41867d15dfdb1dec20203f5907eb"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "2c5688a82f7d39b0fceaf4458856549b1bce695a160a864f41b12b42e86e3745"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { F4 87 5D F4 5B 9C 51 8B 4C 24 04 8D 49 2A 87 4C 24 04 89 4C }

	condition:
		all of them
}