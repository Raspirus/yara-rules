
rule ELASTIC_Linux_Trojan_Mirai_268Aac0B : FILE MEMORY
{
	meta:
		description = "Detects Linux Trojan Mirai (Linux.Trojan.Mirai)"
		author = "Elastic Security"
		id = "268aac0b-c5c7-4035-8381-4e182de91e32"
		date = "2021-01-12"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Trojan_Mirai.yar#L1-L19"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "49c94d184d7e387c3efe34ae6f021e011c3046ae631c9733ab0a230d5fe28ead"
		logic_hash = "6eae3aba35d3379fa194b66a1b4e0d78d0d0b88386cd4ea5dfeb3c072642c7ba"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "9c581721bf82af7dc6482a2c41af5fb3404e01c82545c7b2b29230f707014781"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { 24 18 0F B7 44 24 20 8B 54 24 1C 83 F9 01 8B 7E 0C 89 04 24 8B }

	condition:
		all of them
}