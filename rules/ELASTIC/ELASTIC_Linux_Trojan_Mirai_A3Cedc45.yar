rule ELASTIC_Linux_Trojan_Mirai_A3Cedc45 : FILE MEMORY
{
	meta:
		description = "Detects Linux Trojan Mirai (Linux.Trojan.Mirai)"
		author = "Elastic Security"
		id = "a3cedc45-962d-44b5-bf0e-67166fa6c1a4"
		date = "2021-01-12"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Trojan_Mirai.yar#L851-L869"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "1ae0cd7e5bac967e31771873b4b41a1887abddfcdfcc76fa9149bb2054b03ca4"
		logic_hash = "9233e6faa43d8ea43ff3c71ecb5248d5d311b2a593825c299cac4466278cd020"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "8335e540adfeacdf8f45c9cb36b08fea7a06017bb69aa264dc29647e7ca4a541"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { 74 2C 48 8B 03 48 83 E0 FE 48 29 C3 48 8B 43 08 48 83 E0 FE 4A 8D }

	condition:
		all of them
}