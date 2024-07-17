
rule ELASTIC_Linux_Trojan_Kinsing_196523Fa : FILE MEMORY
{
	meta:
		description = "Detects Linux Trojan Kinsing (Linux.Trojan.Kinsing)"
		author = "Elastic Security"
		id = "196523fa-2bb5-4ada-b929-ddc3d5505b73"
		date = "2021-01-12"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Trojan_Kinsing.yar#L1-L18"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		logic_hash = "baa5808fcf22700ae96844dbf8cb3bec52425eec365d2ba4c71b73ece11a69a2"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "29fa6e4fe5cbcd5c927e6b065f3354e4e9015e65814400687b2361fc9a951c74"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { 64 65 38 5F 00 64 48 8B 0C 25 F8 FF FF FF 48 3B 61 10 76 35 48 83 }

	condition:
		all of them
}