
rule ELASTIC_Linux_Trojan_Mirai_0Bfc17Bd : FILE MEMORY
{
	meta:
		description = "Detects Linux Trojan Mirai (Linux.Trojan.Mirai)"
		author = "Elastic Security"
		id = "0bfc17bd-49bb-4721-9653-0920b631b1de"
		date = "2022-01-05"
		modified = "2022-01-26"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Trojan_Mirai.yar#L1762-L1780"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "1cdd94f2a1cb2b93134646c171d947e325a498f7a13db021e88c05a4cbb68903"
		logic_hash = "ef83bc9ae3c881d09b691db42a1712b500a5bb8df34060a6786cfdc6caaf5530"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "d67e4e12e74cbd31037fae52cf7bad8d8d5b4240d79449fa1ebf9a271af008e1"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { 54 24 64 0F CD 48 8D 14 52 41 0F B6 4C D7 14 D3 E8 01 C5 83 7C 24 }

	condition:
		all of them
}