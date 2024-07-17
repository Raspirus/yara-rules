rule ELASTIC_Linux_Trojan_Tsunami_7C545Abf : FILE MEMORY
{
	meta:
		description = "Detects Linux Trojan Tsunami (Linux.Trojan.Tsunami)"
		author = "Elastic Security"
		id = "7c545abf-822d-44bb-8ac9-1b7e4f27698d"
		date = "2021-04-06"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Trojan_Tsunami.yar#L380-L398"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "95691c7ad1d80f7f1b5541e1d1a1dbeba30a26702a4080d256f14edb75851c5d"
		logic_hash = "fa50ccc4c85417d18a84b7f117f853609c44b17c488a937cdc7495e2d32757f7"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "4141069d6c41c0c26b53a8a86fd675f09982ca6e99757a04ef95b9ad0b8efefa"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { 03 FC DF 40 9C B8 20 07 09 20 35 15 11 03 20 85 }

	condition:
		all of them
}