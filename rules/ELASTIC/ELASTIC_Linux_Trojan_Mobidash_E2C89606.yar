rule ELASTIC_Linux_Trojan_Mobidash_E2C89606 : FILE MEMORY
{
	meta:
		description = "Detects Linux Trojan Mobidash (Linux.Trojan.Mobidash)"
		author = "Elastic Security"
		id = "e2c89606-511c-403a-a4eb-d18dc7aca444"
		date = "2021-01-12"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Trojan_Mobidash.yar#L41-L59"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "6694640e7df5308a969ef40f86393a65febe51639069cb7eaa5650f62c1f4083"
		logic_hash = "64cb8d8ec04a53f663b216208279afba3c10f148fe99822f9a45100a4f73ed28"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "91c51f6af18389f2efb0032e0b775df68f34b66795c05623dccb67266c04214b"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { 13 49 89 C7 4C 89 E6 48 89 DF FF 92 B8 00 00 00 31 C9 4C 89 FA 4C }

	condition:
		all of them
}