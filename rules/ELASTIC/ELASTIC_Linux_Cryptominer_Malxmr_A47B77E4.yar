
rule ELASTIC_Linux_Cryptominer_Malxmr_A47B77E4 : FILE MEMORY
{
	meta:
		description = "Detects Linux Cryptominer Malxmr (Linux.Cryptominer.Malxmr)"
		author = "Elastic Security"
		id = "a47b77e4-0d8d-4714-8527-7b783f0f27b8"
		date = "2021-01-12"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Cryptominer_Malxmr.yar#L61-L79"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "995b43ccb20343494e314824343a567fd85f430e241fdeb43704d9d4937d76cc"
		logic_hash = "bd2b14c8b8e2649af837224fadb32bf0fb67ac403189063a8cb10ad344fb8015"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "635a35defde186972cd6626bd75a1e557a1a9008ab93b38ef1a3635b3210354b"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { 8D 48 49 5E 97 87 DC 73 86 19 51 B3 36 1A 6E FC 8C CC 2C 6E 0B }

	condition:
		all of them
}