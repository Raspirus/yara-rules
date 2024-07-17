rule ELASTIC_Linux_Generic_Threat_9Cf10F10 : FILE MEMORY
{
	meta:
		description = "Detects Linux Generic Threat (Linux.Generic.Threat)"
		author = "Elastic Security"
		id = "9cf10f10-9a5b-46b5-ae25-7239b8f1434a"
		date = "2024-02-01"
		modified = "2024-02-13"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Generic_Threat.yar#L510-L528"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "d07c9be37dc37f43a54c8249fe887dbc4058708f238ff3d95ed21f874cbb84e8"
		logic_hash = "ca4ae64b73fb7013008e8049d17479032d904a3faf5ad0f2ad079971a231a3b8"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "88b3122e747e685187a7b7268e22d12fbd16a24c7c2edb6f7e09c86327fc2f0e"
		severity = 50
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a1 = { 14 8B 44 24 18 8B 08 89 0C 24 89 44 24 04 C6 44 24 08 00 E8 84 1E 00 00 8B 44 24 0C 89 44 24 10 8B 4C 24 18 8B 09 89 04 24 8B 54 24 1C 89 54 24 04 89 4C 24 08 E8 52 C7 05 00 8B 44 24 }

	condition:
		all of them
}