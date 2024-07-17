
rule ELASTIC_Linux_Trojan_Mirai_449937Aa : FILE MEMORY
{
	meta:
		description = "Detects Linux Trojan Mirai (Linux.Trojan.Mirai)"
		author = "Elastic Security"
		id = "449937aa-682a-4906-89ab-80d7127e461e"
		date = "2021-01-12"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Trojan_Mirai.yar#L1105-L1123"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "6f27766534445cffb097c7c52db1fca53b2210c1b10b75594f77c34dc8b994fe"
		logic_hash = "d459e46893115dbdef46bcaceb6a66255ef3a389f1bf7173b0e0bd0d8ce024fb"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "cf2c6b86830099f039b41aeaafbffedfb8294a1124c499e99a11f48a06cd1dfd"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { 00 00 5B 72 65 73 6F 6C 76 5D 20 46 6F 75 6E 64 20 49 50 20 }

	condition:
		all of them
}