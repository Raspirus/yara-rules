rule ELASTIC_Linux_Trojan_Mirai_D33095D4 : FILE MEMORY
{
	meta:
		description = "Detects Linux Trojan Mirai (Linux.Trojan.Mirai)"
		author = "Elastic Security"
		id = "d33095d4-ea02-4588-9852-7493f6781bb4"
		date = "2021-04-06"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Trojan_Mirai.yar#L1581-L1599"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "72326a3a9160e9481dd6fc87159f7ebf8a358f52bf0c17fbc3df80217d032635"
		logic_hash = "b7feaec65d72907d08c98b09fb4ac494ceee7d7bd51c09063363c617e3f057a4"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "20c0faab6aef6e0f15fd34f9bd173547f3195c096eb34c4316144b19d2ab1dc4"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { 00 00 66 83 7C 24 54 FF 66 89 46 04 0F 85 CB }

	condition:
		all of them
}