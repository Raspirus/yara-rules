
rule ELASTIC_Linux_Cryptominer_Stak_D707Fd3A : FILE MEMORY
{
	meta:
		description = "Detects Linux Cryptominer Stak (Linux.Cryptominer.Stak)"
		author = "Elastic Security"
		id = "d707fd3a-41ce-4f88-ad42-d663094db5fb"
		date = "2021-01-12"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Cryptominer_Stak.yar#L40-L58"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "d0d2bab33076121cf6a0a2c4ff1738759464a09ae4771c39442a865a76daff59"
		logic_hash = "b825247372aace6e3ce0ff1d9685b6bb041b7277f8967d5f5926b49813cfadc9"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "c218a3c637f58a6e0dc2aa774eb681757c94e1d34f622b4ee5520985b893f631"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { C2 01 48 89 10 49 8B 55 00 48 8B 02 48 8B 4A 10 48 39 C8 74 9E 80 }

	condition:
		all of them
}