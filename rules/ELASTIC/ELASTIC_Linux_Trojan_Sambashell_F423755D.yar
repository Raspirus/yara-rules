
rule ELASTIC_Linux_Trojan_Sambashell_F423755D : FILE MEMORY
{
	meta:
		description = "Detects Linux Trojan Sambashell (Linux.Trojan.Sambashell)"
		author = "Elastic Security"
		id = "f423755d-60ec-4442-beb1-0820df0fe00b"
		date = "2021-01-12"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Trojan_Sambashell.yar#L1-L19"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "bd8a3728a59afbf433799578ef597b9a7211c8d62e87a25209398814851a77ea"
		logic_hash = "b93c671fae87cd635679142d248cb2b754389ba3b416f3370ea331640eb906ab"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "ea13320c358cadc8187592de73ceb260a00f28907567002d4f093be21f111f74"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { 00 01 00 00 00 FC 0E 00 00 FC 1E 00 00 FC 1E 00 00 74 28 00 00 }

	condition:
		all of them
}