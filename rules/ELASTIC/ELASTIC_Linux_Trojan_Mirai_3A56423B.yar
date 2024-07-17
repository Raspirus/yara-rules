rule ELASTIC_Linux_Trojan_Mirai_3A56423B : FILE MEMORY
{
	meta:
		description = "Detects Linux Trojan Mirai (Linux.Trojan.Mirai)"
		author = "Elastic Security"
		id = "3a56423b-c0cf-4483-87e3-552beb40563a"
		date = "2021-01-12"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Trojan_Mirai.yar#L1028-L1045"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		logic_hash = "0c2765a5c1b331eb9ff5e542bc72eff7be3506e6caef94128413d500086715c6"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "117d6eb47f000c9d475119ca0e6a1b49a91bbbece858758aaa3d7f30d0777d75"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { 24 1C 8B 44 24 20 0F B6 D0 C1 E8 08 89 54 24 24 89 44 24 20 BA 01 00 }

	condition:
		all of them
}