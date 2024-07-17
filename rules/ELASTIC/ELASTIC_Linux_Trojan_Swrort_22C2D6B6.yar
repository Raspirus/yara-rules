rule ELASTIC_Linux_Trojan_Swrort_22C2D6B6 : FILE MEMORY
{
	meta:
		description = "Detects Linux Trojan Swrort (Linux.Trojan.Swrort)"
		author = "Elastic Security"
		id = "22c2d6b6-d100-4310-87c4-3912a86bdd40"
		date = "2021-01-12"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Trojan_Swrort.yar#L41-L59"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "6df073767f48dd79f98e60aa1079f3ab0b89e4f13eedc1af3c2c073e5e235bbc"
		logic_hash = "f661544d267a55feec786ab3d4fc4f002afa8e2b58833461f56b745ec65acfd4"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "d2b16da002cb708cb82f8b96c7d31f15c9afca69e89502b1970758294e91f9a4"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { 31 DB F7 E3 53 43 53 6A 02 89 E1 B0 66 CD 80 51 6A 04 54 6A 02 }

	condition:
		all of them
}