
rule ELASTIC_Linux_Trojan_Mirai_Ec591E81 : FILE MEMORY
{
	meta:
		description = "Detects Linux Trojan Mirai (Linux.Trojan.Mirai)"
		author = "Elastic Security"
		id = "ec591e81-8594-4317-89b0-0fb4d43e14c1"
		date = "2021-01-12"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Trojan_Mirai.yar#L1224-L1242"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "7d45a4a128c25f317020b5d042ab893e9875b6ff0ef17482b984f5b3fe87e451"
		logic_hash = "f2a147fe7f98d2b3141a1fda118ee803c81d9bc6f498bfaf3557665397eb44da"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "fe3d305202ca5376be7103d0b40f746fc26f8e442f8337a1e7c6d658b00fc4aa"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { 22 01 00 00 0E 00 00 00 18 03 00 7F E9 38 32 C9 4D 04 9A 3C }

	condition:
		all of them
}