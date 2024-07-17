
rule ELASTIC_Linux_Trojan_Mirai_A39Dfaa7 : FILE MEMORY
{
	meta:
		description = "Detects Linux Trojan Mirai (Linux.Trojan.Mirai)"
		author = "Elastic Security"
		id = "a39dfaa7-7d2c-4d40-bea5-bbebad522fa4"
		date = "2021-01-12"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Trojan_Mirai.yar#L677-L694"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		logic_hash = "98fde36fc412b6aa50c80c12118975a6bf754a9fba94f1cc3cdeed22565d6b0d"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "95d12cb127c088d55fb0090a1cb0af8e0a02944ff56fd18bcb0834b148c17ad7"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { 00 6C 72 00 00 50 E8 4E 0C 00 00 EB 0E 5A 58 59 97 60 8A 54 }

	condition:
		all of them
}