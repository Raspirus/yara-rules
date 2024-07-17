
rule ELASTIC_Linux_Trojan_Mirai_5946F41B : FILE MEMORY
{
	meta:
		description = "Detects Linux Trojan Mirai (Linux.Trojan.Mirai)"
		author = "Elastic Security"
		id = "5946f41b-594c-4fde-827c-616a99f6fc1b"
		date = "2021-01-12"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Trojan_Mirai.yar#L338-L356"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "f0b6bf8a683f8692973ea8291129c9764269a6739650ec3f9ee50d222df0a38a"
		logic_hash = "43691675db419426413ccc24aa9dfe94456fa1007630652b08a625eafd1f17b8"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "f28b9b311296fc587eced94ca0d80fc60ee22344e5c38520ab161d9f1273e328"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { 59 08 AA 3A 4C D3 6C 2E 6E F7 24 54 32 7C 61 39 65 21 66 74 }

	condition:
		all of them
}