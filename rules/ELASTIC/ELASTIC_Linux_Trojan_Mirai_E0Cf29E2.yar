
rule ELASTIC_Linux_Trojan_Mirai_E0Cf29E2 : FILE MEMORY
{
	meta:
		description = "Detects Linux Trojan Mirai (Linux.Trojan.Mirai)"
		author = "Elastic Security"
		id = "e0cf29e2-88d7-4aa4-b60a-c24626f2b246"
		date = "2021-01-12"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Trojan_Mirai.yar#L1423-L1440"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		logic_hash = "693e27da8cbab32954cc2c9ba648151ad9fc21fe53251628145d7b436ec5e976"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "3f124c3c9f124264dfbbcca1e4b4d7cfcf3274170d4bf8966b6559045873948f"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { 83 FE 01 76 12 0F B7 07 83 EE 02 48 83 C7 02 48 01 C2 83 FE 01 }

	condition:
		all of them
}