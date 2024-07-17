
rule ELASTIC_Linux_Trojan_Iroffer_7478Ddd9 : FILE MEMORY
{
	meta:
		description = "Detects Linux Trojan Iroffer (Linux.Trojan.Iroffer)"
		author = "Elastic Security"
		id = "7478ddd9-ebb6-4bd4-a1ad-d0bf8f99ab1d"
		date = "2021-01-12"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Trojan_Iroffer.yar#L81-L99"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "20e1509c23d7ef14b15823e4c56b9a590e70c5b7960a04e94b662fc34152266c"
		logic_hash = "e650ee830b735a11088b628e865cd40a15054437ca05849f2eaa7838eac152e3"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "b497ee116b77e2ba1fedfad90894d956806a2ffa19cadc33a916513199b0a381"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { 80 FA 0F 74 10 80 FA 16 74 0B 80 FA 1F 74 06 C6 04 1E 2E 89 }

	condition:
		all of them
}