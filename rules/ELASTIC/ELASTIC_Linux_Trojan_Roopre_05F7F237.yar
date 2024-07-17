
rule ELASTIC_Linux_Trojan_Roopre_05F7F237 : FILE MEMORY
{
	meta:
		description = "Detects Linux Trojan Roopre (Linux.Trojan.Roopre)"
		author = "Elastic Security"
		id = "05f7f237-dcc5-4f0d-8baa-290137eea9c5"
		date = "2021-01-12"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Trojan_Roopre.yar#L21-L39"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "36ae2bf773135fdb0ead7fbbd46f90fd41d6f973569de1941c8723158fc6cfcc"
		logic_hash = "12e14ac31932033f2448b7a3bfd6ce826fff17494547ac4baefb20f6713baf5f"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "2f1d7fd2d0104be63180003ae225eafa95f9d967154d3972782502742bbedf43"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { 01 3A 74 06 80 7F 02 5C 75 1F 48 83 C7 03 B2 5C EB E8 38 D1 48 8D }

	condition:
		all of them
}