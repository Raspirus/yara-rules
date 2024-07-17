rule ELASTIC_Linux_Cryptominer_Camelot_209B02Dd : FILE MEMORY
{
	meta:
		description = "Detects Linux Cryptominer Camelot (Linux.Cryptominer.Camelot)"
		author = "Elastic Security"
		id = "209b02dd-3087-475b-8d28-baa18647685b"
		date = "2021-04-06"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Cryptominer_Camelot.yar#L278-L296"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "60d33d1fdabc6b10f7bb304f4937051a53d63f39613853836e6c4d095343092e"
		logic_hash = "5cadc955242d4b7d5fd4365a0b425051d89c905e3d49ea03967150de0020225c"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "5829daea974d581bb49ac08150b63b7b24e6fae68f669b6b7ab48418560894d4"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { 45 31 F5 44 0B 5C 24 F4 41 C1 EA 10 44 0B 54 24 }

	condition:
		all of them
}