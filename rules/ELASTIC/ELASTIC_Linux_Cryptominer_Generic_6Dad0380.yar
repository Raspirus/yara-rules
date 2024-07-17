rule ELASTIC_Linux_Cryptominer_Generic_6Dad0380 : FILE MEMORY
{
	meta:
		description = "Detects Linux Cryptominer Generic (Linux.Cryptominer.Generic)"
		author = "Elastic Security"
		id = "6dad0380-7771-4fb9-a7e5-176eeb6fcfd7"
		date = "2021-01-12"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Cryptominer_Generic.yar#L741-L759"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "628b1cc8ccdbe2ae0d4ef621da047e07e2532d00fe3d4da65f0a0bcab20fb546"
		logic_hash = "b305448d5517212adb7586e7af12842095e1a263520511329e40f0865fe4f81b"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "ffe022f42e98c9c1eeb3aead0aca9d795200b4b22f89e7f3b03baf96f18c9473"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { 48 C1 E6 05 48 01 C6 48 39 F1 74 05 49 89 74 24 08 44 89 E9 48 C1 }

	condition:
		all of them
}