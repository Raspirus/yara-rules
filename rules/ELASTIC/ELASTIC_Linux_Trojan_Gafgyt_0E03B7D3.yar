rule ELASTIC_Linux_Trojan_Gafgyt_0E03B7D3 : FILE MEMORY
{
	meta:
		description = "Detects Linux Trojan Gafgyt (Linux.Trojan.Gafgyt)"
		author = "Elastic Security"
		id = "0e03b7d3-a6b0-46a0-920e-c15ee7e723f7"
		date = "2021-01-12"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Trojan_Gafgyt.yar#L1070-L1087"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		logic_hash = "845be03fac893f8e914aabda5206000dc07947ade0b8f46cc5d58d8458f035f6"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "1bf1f271005328669b3eb4940e2b75eff9fc47208d79a12196fd7ce04bc4dbe8"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { F5 74 84 32 63 29 5A B2 78 FF F7 FA 0E 51 B3 2F CD 7F 10 FA }

	condition:
		all of them
}