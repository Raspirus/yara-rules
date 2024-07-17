rule ELASTIC_Linux_Cryptominer_Generic_397A86Bd : FILE MEMORY
{
	meta:
		description = "Detects Linux Cryptominer Generic (Linux.Cryptominer.Generic)"
		author = "Elastic Security"
		id = "397a86bd-6d66-4db0-ad41-d0ae3dbbeb21"
		date = "2021-01-12"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Cryptominer_Generic.yar#L41-L59"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "79c47a80ecc6e0f5f87749319f6d5d6a3f0fbff7c34082d747155b9b20510cde"
		logic_hash = "6b46a82d1aea0357f5a48c9ae1d93e3d4d31bd98b9c9b4e0b0d0629e7f159499"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "0bad343f28180822bcb45b0a84d69b40e26e5eedb650db1599514020b6736dd0"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { 74 4F 48 8B 75 00 48 8B 4D 08 4C 89 F7 48 8B 55 10 48 8B 45 18 48 89 74 }

	condition:
		all of them
}