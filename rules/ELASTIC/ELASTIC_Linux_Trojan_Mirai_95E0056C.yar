
rule ELASTIC_Linux_Trojan_Mirai_95E0056C : FILE MEMORY
{
	meta:
		description = "Detects Linux Trojan Mirai (Linux.Trojan.Mirai)"
		author = "Elastic Security"
		id = "95e0056c-bc07-42cf-89ab-6c0cde3ccc8a"
		date = "2021-01-12"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Trojan_Mirai.yar#L1383-L1401"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "45f67d4c18abc1bad9a9cc6305983abf3234cd955d2177f1a72c146ced50a380"
		logic_hash = "9e34891d28034d1f4fc3da5cb99df8fc74f0b876903088f5eab5fe36e0e0e603"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "a2550fdd2625f85050cfe53159858207a79e8337412872aaa7b4627b13cb6c94"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { 50 46 00 13 10 11 16 17 00 57 51 47 50 00 52 43 51 51 00 43 }

	condition:
		all of them
}