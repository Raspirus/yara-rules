
rule ELASTIC_Linux_Cryptominer_Generic_Fdd7340F : FILE MEMORY
{
	meta:
		description = "Detects Linux Cryptominer Generic (Linux.Cryptominer.Generic)"
		author = "Elastic Security"
		id = "fdd7340f-49d6-4770-afac-24104a3c2f86"
		date = "2021-01-12"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Cryptominer_Generic.yar#L681-L699"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "de59bee1793b88e7b48b6278a52e579770f5204e92042142cc3a9b2d683798dd"
		logic_hash = "fd39ba5cf050d23de0889feefa9cd74dfb6385a09aa9dba90dc1d5d6cb020867"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "cc302eb6c133901cc3aa78e6ca0af16a620eb4dabb16b21d9322c4533f11d25f"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { EA 48 89 DE 48 8D 7C 24 08 FF 53 18 48 8B 44 24 08 48 83 78 }

	condition:
		all of them
}