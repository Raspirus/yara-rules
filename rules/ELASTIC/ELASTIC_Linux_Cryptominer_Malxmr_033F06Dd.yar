rule ELASTIC_Linux_Cryptominer_Malxmr_033F06Dd : FILE MEMORY
{
	meta:
		description = "Detects Linux Cryptominer Malxmr (Linux.Cryptominer.Malxmr)"
		author = "Elastic Security"
		id = "033f06dd-f3ed-4140-bbff-138ed2d8378c"
		date = "2021-01-12"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Cryptominer_Malxmr.yar#L260-L278"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "3afc8d2d85aca61108d21f82355ad813eba7a189e81dde263d318988c5ea50bd"
		logic_hash = "a0c788dbcd43cab2af1614d5d90ed9e07a45b547241f729e09709d2a1ec24e60"
		score = 75
		quality = 73
		tags = "FILE, MEMORY"
		fingerprint = "2f1f39e10df0ca6c133237b6d92afcb8a9c23de511120e8860c1e6ed571252ed"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { 42 68 63 33 4E 33 5A 48 78 6A 64 58 51 67 4C 57 51 36 49 43 31 }

	condition:
		all of them
}