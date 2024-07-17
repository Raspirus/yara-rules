rule ELASTIC_Linux_Trojan_Mirai_Dca3B9B4 : FILE MEMORY
{
	meta:
		description = "Detects Linux Trojan Mirai (Linux.Trojan.Mirai)"
		author = "Elastic Security"
		id = "dca3b9b4-62f3-41ed-a3b3-80dd0990f8c5"
		date = "2021-01-12"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Trojan_Mirai.yar#L1502-L1520"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "a839437deba6d30e7a22104561e38f60776729199a96a71da3a88a7c7990246a"
		logic_hash = "f85dfc1c00706d7ac11ef35c41c471383ef8b019a5c2566b27072a5ef5ad5c93"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "b0471831229be1bcbcf6834e2d1a5b85ed66fb612868c2c207fe009ae2a0e799"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { 83 45 F4 01 8B 45 F4 3B 45 F0 75 11 48 8B 45 F8 48 2B 45 D8 }

	condition:
		all of them
}