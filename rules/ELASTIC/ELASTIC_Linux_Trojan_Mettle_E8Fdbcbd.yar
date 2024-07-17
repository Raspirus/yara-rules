rule ELASTIC_Linux_Trojan_Mettle_E8Fdbcbd : FILE MEMORY
{
	meta:
		description = "Detects Linux Trojan Mettle (Linux.Trojan.Mettle)"
		author = "Elastic Security"
		id = "e8fdbcbd-84d3-4c42-986b-c8d5d940a96a"
		date = "2024-05-06"
		modified = "2024-05-21"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Trojan_Mettle.yar#L1-L23"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "864eae4f27648b8a9d9b0eb1894169aa739311cdd02b1435a34881acf7059d58"
		logic_hash = "d13c1e7fb815ebbefa78922e9b85a1ced015c03b8f1b2cf1885a9c483b8e0ab3"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "2038686308a77286ed5d13b408962075933da7ca5772d46b65e5f247193036b5"
		severity = 100
		arch_context = "x86, arm64"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$mettle1 = "mettlesploit!"
		$mettle2 = "/mettle/mettle/src/"
		$mettle3 = "mettle_get_c2"
		$mettle4 = "mettle_console_start_interactive"
		$mettle5 = "mettle_get_machine_id"

	condition:
		2 of ($mettle*)
}