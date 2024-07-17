
rule ELASTIC_Linux_Trojan_Tsunami_Ad60D7E8 : FILE MEMORY
{
	meta:
		description = "Detects Linux Trojan Tsunami (Linux.Trojan.Tsunami)"
		author = "Elastic Security"
		id = "ad60d7e8-0823-4bfa-b823-681c554bf297"
		date = "2021-01-12"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Trojan_Tsunami.yar#L321-L338"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		logic_hash = "1253a8cd1a5230f1ec1f8c7ecd07f89f28acf5c2aa92395c6cb9e635c16a1e25"
		score = 75
		quality = 73
		tags = "FILE, MEMORY"
		fingerprint = "e1ca4c566307238a5d8cd16db8d0d528626e0b92379177b167ce25b4c88d10ce"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { 4E 4F 54 49 43 45 20 25 73 20 3A 53 70 6F 6F 66 73 3A 20 25 64 2E 25 64 2E 25 64 2E 25 64 }

	condition:
		all of them
}