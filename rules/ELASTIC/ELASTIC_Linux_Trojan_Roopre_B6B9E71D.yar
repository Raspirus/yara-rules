rule ELASTIC_Linux_Trojan_Roopre_B6B9E71D : FILE MEMORY
{
	meta:
		description = "Detects Linux Trojan Roopre (Linux.Trojan.Roopre)"
		author = "Elastic Security"
		id = "b6b9e71d-7f1c-4827-b659-f9dad5667d69"
		date = "2021-01-12"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Trojan_Roopre.yar#L1-L19"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "36ae2bf773135fdb0ead7fbbd46f90fd41d6f973569de1941c8723158fc6cfcc"
		logic_hash = "32294e476a014a919d2d738bdc940a7fc5f91e1b13c005f164a5b6bf84eb2635"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "1a87cccd06b99e0375ffef17d4b3c5fd8957013ab8de7507e9b8d1174573a6cf"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { 54 24 08 48 C7 C6 18 FC FF FF 49 8B 4A 08 48 89 C8 48 99 48 }

	condition:
		all of them
}