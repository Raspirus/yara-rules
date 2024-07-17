rule ELASTIC_Linux_Trojan_Mirai_D5Da717F : FILE MEMORY
{
	meta:
		description = "Detects Linux Trojan Mirai (Linux.Trojan.Mirai)"
		author = "Elastic Security"
		id = "d5da717f-3344-41a8-884e-8944172ea370"
		date = "2021-04-06"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Trojan_Mirai.yar#L1561-L1579"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "1f6bcdfc7d1c56228897cd7548266bb0b9a41b913be354036816643ac21b6f66"
		logic_hash = "034dae5bea7536e8c8aa22b8b891b9c991b94f04be12c9fe6d78ddf07a2365d9"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "c3674075a435ef1cd9e568486daa2960450aa7ffa8e5dbf440a50e01803ea2f3"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { 00 00 66 83 7C 24 34 FF 66 89 46 2C 0F 85 C2 }

	condition:
		all of them
}