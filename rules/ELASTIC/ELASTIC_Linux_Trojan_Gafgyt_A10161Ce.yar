
rule ELASTIC_Linux_Trojan_Gafgyt_A10161Ce : FILE MEMORY
{
	meta:
		description = "Detects Linux Trojan Gafgyt (Linux.Trojan.Gafgyt)"
		author = "Elastic Security"
		id = "a10161ce-62e0-4f60-9de7-bd8caf8618be"
		date = "2021-01-12"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Trojan_Gafgyt.yar#L140-L157"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		logic_hash = "12ba13a746300d1ab1d0386b86ec224eebf4e6d0b3688495c2fee6a7eccc361d"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "77e89011a67a539954358118d41ad3dabde0e69bac2bbb2b2da18eaad427d935"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { 45 B0 8B 45 BC 48 63 D0 48 89 D0 48 C1 E0 02 48 8D 14 10 48 8B }

	condition:
		all of them
}