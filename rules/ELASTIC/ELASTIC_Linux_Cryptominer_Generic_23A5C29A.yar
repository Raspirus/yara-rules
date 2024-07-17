
rule ELASTIC_Linux_Cryptominer_Generic_23A5C29A : FILE MEMORY
{
	meta:
		description = "Detects Linux Cryptominer Generic (Linux.Cryptominer.Generic)"
		author = "Elastic Security"
		id = "23a5c29a-6a8f-46f4-87ba-2a60139450ce"
		date = "2021-01-12"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Cryptominer_Generic.yar#L121-L139"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "1320d7a2b5e3b65fe974a95374b4ea7ed1a5aa27d76cd3d9517d3a271121103f"
		logic_hash = "c2608e7ee73102e0737a859a18c5482877c6dc0e597d8a14d8d41f5e01a0b1f4"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "1a7a86ff6e1666c2da6e6f65074bb1db2fe1c97d1ad42d1f670dd5c88023eecf"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { C1 48 29 D0 48 01 C0 4D 8B 39 48 29 C1 49 29 F8 48 8D 04 C9 4D 8D }

	condition:
		all of them
}