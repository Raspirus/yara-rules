
rule ELASTIC_Linux_Trojan_Mirai_3B9675Fd : FILE MEMORY
{
	meta:
		description = "Detects Linux Trojan Mirai (Linux.Trojan.Mirai)"
		author = "Elastic Security"
		id = "3b9675fd-1fa1-4e15-9472-64cb93315d63"
		date = "2021-01-12"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Trojan_Mirai.yar#L1661-L1679"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "4ec4bc88156bd51451fdaf0550c21c799c6adacbfc654c8ec634ebca3383bd66"
		logic_hash = "61ff7cb8d664291de5cf0c82b80cf0f4001c41d3f02b7f4762f67eb8128df15d"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "40a154bafa72c5aa0c085ac2b92b5777d1acecfd28d28b15c7229ba5c59435f2"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { 78 10 85 C9 75 65 48 8B 8C 24 A0 00 00 00 48 89 48 10 0F B6 4C }

	condition:
		all of them
}