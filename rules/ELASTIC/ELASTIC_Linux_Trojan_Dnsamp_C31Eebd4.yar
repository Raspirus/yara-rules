
rule ELASTIC_Linux_Trojan_Dnsamp_C31Eebd4 : FILE MEMORY
{
	meta:
		description = "Detects Linux Trojan Dnsamp (Linux.Trojan.Dnsamp)"
		author = "Elastic Security"
		id = "c31eebd4-7709-440d-95d1-f9a3071cc5ca"
		date = "2021-01-12"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Trojan_Dnsamp.yar#L1-L19"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "4b86de97819a49a90961d59f9c3ab9f8e57e19add9fe1237d2a2948b4ff22de6"
		logic_hash = "b998065eff9f67a1cdf19644a13edb0cef3c619d8b6e16c412d58f5d538e4617"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "220b656a51b3041ede4ffe8f509657c393ff100c88b401c802079aae5804dacd"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { 45 F8 8B 40 14 48 63 D0 48 8D 45 E0 48 8D 70 04 48 8B 45 F8 48 8B }

	condition:
		all of them
}