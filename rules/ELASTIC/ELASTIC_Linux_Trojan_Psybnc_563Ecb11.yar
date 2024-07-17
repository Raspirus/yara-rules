rule ELASTIC_Linux_Trojan_Psybnc_563Ecb11 : FILE MEMORY
{
	meta:
		description = "Detects Linux Trojan Psybnc (Linux.Trojan.Psybnc)"
		author = "Elastic Security"
		id = "563ecb11-e215-411f-8583-7cb7b2956252"
		date = "2021-01-12"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Trojan_Psybnc.yar#L1-L19"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "f77216b169e8d12f22ef84e625159f3a51346c2b6777a1fcfb71268d17b06d39"
		logic_hash = "b93e6ab097ccd4c348d228a48df098594e560e62256bfe019669ca9488221214"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "1e7a2a6240d6f7396505cc2203c03d4ae93a7ef0c0c956cef7a390b4303a2cbe"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { 5F 65 6E 00 6B 6F 5F 65 6E 00 72 75 5F 65 6E 00 65 73 5F 65 6E 00 44 }

	condition:
		all of them
}