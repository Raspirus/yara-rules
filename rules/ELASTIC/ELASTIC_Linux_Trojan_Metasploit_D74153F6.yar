
rule ELASTIC_Linux_Trojan_Metasploit_D74153F6 : FILE MEMORY
{
	meta:
		description = "Detects x86 msfvenom IPv6 TCP reverse shells"
		author = "Elastic Security"
		id = "d74153f6-0047-4576-8c3e-db0525bb3a92"
		date = "2024-05-07"
		modified = "2024-05-21"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Trojan_Metasploit.yar#L139-L159"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "2823d27492e2e7a95b67a08cb269eb6f4175451d58b098ae429330913397d40a"
		logic_hash = "c60e7e63183f5bf0354a03f8399576e494e44a30257339ebccb6c19e954d6f3a"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "824baa1ee7fda8074d76e167d3c5cc1911c7224bb72b1add5e360f26689b48c2"
		threat_name = "Linux.Trojan.Metasploit"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$str1 = { 31 DB 53 43 53 6A 0A 89 E1 6A 66 58 CD 80 96 99 }
		$str2 = { 89 E1 6A 1C 51 56 89 E1 43 43 6A 66 58 CD 80 89 F3 B6 0C B0 03 CD 80 89 DF }

	condition:
		all of them
}