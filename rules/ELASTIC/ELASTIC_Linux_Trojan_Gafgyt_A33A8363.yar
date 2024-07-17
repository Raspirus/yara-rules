
rule ELASTIC_Linux_Trojan_Gafgyt_A33A8363 : FILE MEMORY
{
	meta:
		description = "Detects Linux Trojan Gafgyt (Linux.Trojan.Gafgyt)"
		author = "Elastic Security"
		id = "a33a8363-5511-4fe1-a0d8-75156b9ccfc7"
		date = "2021-01-12"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Trojan_Gafgyt.yar#L1148-L1165"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		logic_hash = "3fe17dc43f07dacdad6ababf141983854b977e244c0af824fea0ab953ad70fee"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "74f964eaadbf8f30d40cdec40b603c5141135d2e658e7ce217d0d6c62e18dd08"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { 41 88 02 48 85 D2 75 ED 5A 5B 5D 41 5C 41 5D 4C 89 F0 41 5E }

	condition:
		all of them
}