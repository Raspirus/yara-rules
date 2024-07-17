rule ELASTIC_Linux_Trojan_Mirai_B548632D : FILE MEMORY
{
	meta:
		description = "Detects Linux Trojan Mirai (Linux.Trojan.Mirai)"
		author = "Elastic Security"
		id = "b548632d-7916-444a-aa68-4b3e38251905"
		date = "2021-01-12"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Trojan_Mirai.yar#L1403-L1421"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "639d9d6da22e84fb6b6fc676a1c4cfd74a8ed546ce8661500ab2ef971242df07"
		logic_hash = "bfb46457f8b79548726e3988d649f94e04f26f9e546aae70ece94defae6bab8a"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "8b355e9c1150d43f52e6e9e052eda87ba158041f7b645f4f67c32dd549c09f28"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { 00 0B 01 00 00 0E 00 00 00 18 03 00 7F E9 38 32 C9 4D 04 9A }

	condition:
		all of them
}