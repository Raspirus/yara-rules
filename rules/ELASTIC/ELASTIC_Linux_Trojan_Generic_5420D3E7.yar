
rule ELASTIC_Linux_Trojan_Generic_5420D3E7 : FILE MEMORY
{
	meta:
		description = "Detects Linux Trojan Generic (Linux.Trojan.Generic)"
		author = "Elastic Security"
		id = "5420d3e7-012f-4ce0-bb13-9e5221efa73e"
		date = "2021-01-12"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Trojan_Generic.yar#L21-L39"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "103b8fced0aebd73cb8ba9eff1a55e6b6fa13bb0a099c9234521f298ee8d2f9f"
		logic_hash = "8ba3566ec900e37f05f11d40c65ffe1dfc587c553fa9c28b71ced7a9a90f50c3"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "e81615b5756c2789b9be8fb10420461d5260914e16ba320cbab552d654bbbd8a"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { 63 00 5F 5A 4E 34 41 52 43 34 37 65 6E 63 72 79 70 74 45 50 63 }

	condition:
		all of them
}