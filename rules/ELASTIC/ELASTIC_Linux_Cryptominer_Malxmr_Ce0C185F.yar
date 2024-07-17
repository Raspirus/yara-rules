
rule ELASTIC_Linux_Cryptominer_Malxmr_Ce0C185F : FILE MEMORY
{
	meta:
		description = "Detects Linux Cryptominer Malxmr (Linux.Cryptominer.Malxmr)"
		author = "Elastic Security"
		id = "ce0c185f-fca2-47d3-9e7c-57b541af98a5"
		date = "2021-01-12"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Cryptominer_Malxmr.yar#L280-L298"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "cdd3d567fbcbdd6799afad241ae29acbe4ab549445e5c4fc0678d16e75b40dfa"
		logic_hash = "f88c5a295cc62f5a91e26731fc60aaf450376cbb282f43304ba2a5ac5d149dd4"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "0d2e3e2b04e93f25c500677482e15d92408cb1da2a5e3c5a13dc71e52d140f85"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { EF E5 66 0F 6F AC 24 80 00 00 00 66 0F EB E8 66 0F EF D5 66 0F }

	condition:
		all of them
}