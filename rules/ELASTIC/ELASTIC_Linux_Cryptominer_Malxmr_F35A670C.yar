rule ELASTIC_Linux_Cryptominer_Malxmr_F35A670C : FILE MEMORY
{
	meta:
		description = "Detects Linux Cryptominer Malxmr (Linux.Cryptominer.Malxmr)"
		author = "Elastic Security"
		id = "f35a670c-7599-4c93-b08b-463c4a93808a"
		date = "2021-01-12"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Cryptominer_Malxmr.yar#L220-L238"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "a73808211ba00b92f8d0027831b3aa74db15f068c53dd7f20fcadb294224f480"
		logic_hash = "95a8aeffb7193c3f4adfea5b7f0741a53528620c57cbdb4d471d756db03c6493"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "9064024118d30d89bdc093d5372a0d9fefd43eb1ac6359dbedcf3b73ba93f312"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { 4C 01 CD 48 0F AF D6 48 8D 54 55 00 89 DD 48 31 D7 48 C1 C7 20 }

	condition:
		all of them
}