
rule ELASTIC_Linux_Trojan_Bish_974B4B47 : FILE MEMORY
{
	meta:
		description = "Detects Linux Trojan Bish (Linux.Trojan.Bish)"
		author = "Elastic Security"
		id = "974b4b47-38cf-4460-8ff3-e066e5c8a5fc"
		date = "2021-04-06"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Trojan_Bish.yar#L1-L19"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "9171fd2bbe182f0a3cd35937f3ee0076c9358f52f5bc047498dd9e233ae11757"
		logic_hash = "c5a7d036c89fe50626da51486d19ee731ad28cbc8d36def075d8f33a7b68961f"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "8858f99934e367b7489d60bfaa74ab57e2ae507a8c06fb29693197792f6f5069"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { 00 31 C0 31 DB 31 C9 B0 17 CD 80 31 C0 50 68 6E }

	condition:
		all of them
}