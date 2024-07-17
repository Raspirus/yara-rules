rule ELASTIC_Linux_Cryptominer_Stak_05088561 : FILE MEMORY
{
	meta:
		description = "Detects Linux Cryptominer Stak (Linux.Cryptominer.Stak)"
		author = "Elastic Security"
		id = "05088561-ec73-4068-a7f3-3eff612ecd28"
		date = "2021-01-12"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Cryptominer_Stak.yar#L1-L19"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "d0d2bab33076121cf6a0a2c4ff1738759464a09ae4771c39442a865a76daff59"
		logic_hash = "2b0f8a4efdfb13abcc2a1b43e9c39828ea1de6015fef0ef613bd754da5aa3e9a"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "dfcfa99a2924eb9e8bc0e7b51db6d1b633e742e34add40dc5d1bb90375f85f6e"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { CD 49 8D 4D 07 48 83 E1 F8 48 39 CD 73 55 49 8B 06 48 8B 50 08 48 8D }

	condition:
		all of them
}