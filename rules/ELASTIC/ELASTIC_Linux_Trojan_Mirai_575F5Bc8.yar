
rule ELASTIC_Linux_Trojan_Mirai_575F5Bc8 : FILE MEMORY
{
	meta:
		description = "Detects Linux Trojan Mirai (Linux.Trojan.Mirai)"
		author = "Elastic Security"
		id = "575f5bc8-b848-4db4-a99c-132d4d2bc8a4"
		date = "2021-01-12"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Trojan_Mirai.yar#L1086-L1103"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		logic_hash = "dec143d096f5774f297ce90ef664ae50c40ae4f87843bbb34e496565c0faf3b2"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "58e22a2acd002b07e1b1c546e8dfe9885d5dfd2092d4044630064078038e314f"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { 5A 56 5B 5B 55 42 44 5E 59 52 44 44 00 5E 73 5E 45 52 54 43 00 }

	condition:
		all of them
}