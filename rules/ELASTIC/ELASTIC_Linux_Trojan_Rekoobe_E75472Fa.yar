rule ELASTIC_Linux_Trojan_Rekoobe_E75472Fa : FILE MEMORY
{
	meta:
		description = "Detects Linux Trojan Rekoobe (Linux.Trojan.Rekoobe)"
		author = "Elastic Security"
		id = "e75472fa-0263-4a47-a3bd-2d1bb14df177"
		date = "2021-01-12"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Trojan_Rekoobe.yar#L1-L19"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "8d2a9e363752839a09001a9e3044ab7919daffd9d9aee42d936bc97394164a88"
		logic_hash = "e3e9934ee8ce6933f676949c5b5c82ad044ac32f08fe86697b0a0cf7fb63fc5e"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "4e7605685ba7ba53afeafdef7e46bdca76109bd4d8b9116a93c301edeff606ee"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { 00 00 00 83 F8 01 74 1F 89 D0 48 8B 4C 24 08 64 48 33 0C 25 28 00 }

	condition:
		all of them
}