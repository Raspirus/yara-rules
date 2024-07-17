rule ELASTIC_Linux_Trojan_Lady_75F6392C : FILE MEMORY
{
	meta:
		description = "Detects Linux Trojan Lady (Linux.Trojan.Lady)"
		author = "Elastic Security"
		id = "75f6392c-fc13-4abb-a391-b5f1ea1039d8"
		date = "2022-01-05"
		modified = "2022-01-26"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Trojan_Lady.yar#L1-L19"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "c257ac7bd3a9639e0d67a7db603d5bc8d8505f6f2107a26c2615c5838cf11826"
		logic_hash = "5160b6ab4800c72b48b501787f3164c2ba1061a2abe21c63180e02d6791a4c12"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "da6d4dff230120eed94e04b0e6060713c2bc17da54c098e9a9f3ec7a8200b9bf"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { 57 72 69 00 49 3B 66 10 76 38 48 83 EC 18 48 89 6C 24 10 48 8D 6C }

	condition:
		all of them
}