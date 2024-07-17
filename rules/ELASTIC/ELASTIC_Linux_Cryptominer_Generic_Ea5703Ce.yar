rule ELASTIC_Linux_Cryptominer_Generic_Ea5703Ce : FILE MEMORY
{
	meta:
		description = "Detects Linux Cryptominer Generic (Linux.Cryptominer.Generic)"
		author = "Elastic Security"
		id = "ea5703ce-4ad4-46cc-b253-8d022ca385a3"
		date = "2021-01-12"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Cryptominer_Generic.yar#L141-L159"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "bec6eea63025e2afa5940d27ead403bfda3a7b95caac979079cabef88af5ee0b"
		logic_hash = "bbf0191ecff24fd24376fd3dec2e96644188ca4d26b4ca4f087e212bae2eab85"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "a58a41ab4602380c0989659127d099add042413f11e3815a5e1007a44effaa68"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { 0F 94 C0 EB 05 B8 01 00 00 00 44 21 E8 48 8B 4C 24 08 64 48 33 0C 25 28 00 }

	condition:
		all of them
}