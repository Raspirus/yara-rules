rule ELASTIC_Linux_Trojan_Tsunami_55A80Ab6 : FILE MEMORY
{
	meta:
		description = "Detects Linux Trojan Tsunami (Linux.Trojan.Tsunami)"
		author = "Elastic Security"
		id = "55a80ab6-3de4-48e1-a9de-28dc3edaa104"
		date = "2021-01-12"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Trojan_Tsunami.yar#L161-L179"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "5259495788f730a2a3bad7478c1873c8a6296506a778f18bc68e39ce48b979da"
		logic_hash = "1fc29f98e9ea2a5b67d0a88f37813a5e62b5f1d2a26aee74f90e9ead445dc713"
		score = 75
		quality = 73
		tags = "FILE, MEMORY"
		fingerprint = "2fe3a9e1115d8c2269fe090c57ee3d5b2cd52b4ba1d020cec0135e2f8bbcb50e"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { 74 68 65 20 63 75 72 72 65 6E 74 20 73 70 6F 6F 66 69 6E 67 }

	condition:
		all of them
}