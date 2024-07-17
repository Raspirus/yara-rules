
rule ELASTIC_Linux_Trojan_Mirai_4032Ade1 : FILE MEMORY
{
	meta:
		description = "Detects Linux Trojan Mirai (Linux.Trojan.Mirai)"
		author = "Elastic Security"
		id = "4032ade1-4864-4637-ae73-867cd5fb7378"
		date = "2021-01-12"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Trojan_Mirai.yar#L160-L178"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "6150fbbefb916583a0e888dee8ed3df8ec197ba7c04f89fb24f31de50226e688"
		logic_hash = "9c5e24c4efd4035408897f638d3579c3798139fd18178cee4a944b49c13e1532"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "2b150a6571f5a2475d0b4a2ddb75623d6fa1c861f5385a5c42af24db77573480"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { F8 0C 67 56 55 4C 06 87 DE B2 C0 79 AE 88 73 79 0C 7E F8 87 }

	condition:
		all of them
}