rule ELASTIC_Linux_Cryptominer_Malxmr_Ad09E090 : FILE MEMORY
{
	meta:
		description = "Detects Linux Cryptominer Malxmr (Linux.Cryptominer.Malxmr)"
		author = "Elastic Security"
		id = "ad09e090-098e-461d-b967-e45654b902bb"
		date = "2021-01-12"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Cryptominer_Malxmr.yar#L21-L39"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "cdd3d567fbcbdd6799afad241ae29acbe4ab549445e5c4fc0678d16e75b40dfa"
		logic_hash = "6c2d548ba9f01444e8fe4b0aa8a0556970acac06d39bb7c87446b6b91ab0d129"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "a62729bbe04eca01dbb3c56de63466ed115f30926fc5d203c9bae75a93227e09"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { 24 50 8B 44 24 64 89 54 24 54 39 C3 77 0E 72 08 8B 44 24 60 }

	condition:
		all of them
}