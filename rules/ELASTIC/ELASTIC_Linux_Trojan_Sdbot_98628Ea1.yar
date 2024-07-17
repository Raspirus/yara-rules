rule ELASTIC_Linux_Trojan_Sdbot_98628Ea1 : FILE MEMORY
{
	meta:
		description = "Detects Linux Trojan Sdbot (Linux.Trojan.Sdbot)"
		author = "Elastic Security"
		id = "98628ea1-40d8-4a05-835f-a5a5f83637cb"
		date = "2021-01-12"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Trojan_Sdbot.yar#L1-L19"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "5568ae1f8a1eb879eb4705db5b3820e36c5ecea41eb54a8eef5b742f477cbdd8"
		logic_hash = "55b8e3fa755965b85a043015f9303644b8e06fe8bfdc0e2062de75bdc2881541"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "15cf6b916dd87915738f3aa05a2955c78a357935a183c0f88092d808535625a5"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { 54 00 3C 08 54 00 02 00 26 00 00 40 4D 08 00 5C 00 50 00 49 00 }

	condition:
		all of them
}