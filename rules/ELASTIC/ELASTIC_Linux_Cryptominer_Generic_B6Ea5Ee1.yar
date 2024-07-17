
rule ELASTIC_Linux_Cryptominer_Generic_B6Ea5Ee1 : FILE MEMORY
{
	meta:
		description = "Detects Linux Cryptominer Generic (Linux.Cryptominer.Generic)"
		author = "Elastic Security"
		id = "b6ea5ee1-ede5-4fa3-a065-99219b3530da"
		date = "2021-01-12"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Cryptominer_Generic.yar#L461-L479"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "19b442c9aa229cd724ed9cbaa73f9dfaf0ed61aa3fd1bee7bf8ba964fc23a2b8"
		logic_hash = "529119e07aa0243afddc3141dc441c314c3f75bdf3aee473b8bb7749c95fa78a"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "07c2f1fcb50ce5bcdebfc03fca4aaacdbabab42a857d7cc8f008712ca576b871"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { 47 20 49 8D 77 20 4C 89 74 24 10 4C 89 6C 24 18 4C 89 64 24 20 }

	condition:
		all of them
}