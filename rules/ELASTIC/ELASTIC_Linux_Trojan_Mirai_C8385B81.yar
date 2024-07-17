
rule ELASTIC_Linux_Trojan_Mirai_C8385B81 : FILE MEMORY
{
	meta:
		description = "Detects Linux Trojan Mirai (Linux.Trojan.Mirai)"
		author = "Elastic Security"
		id = "c8385b81-0f5b-41c3-94bb-265ede946a84"
		date = "2021-01-12"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Trojan_Mirai.yar#L199-L217"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "3d27736caccdd3199a14ce29d91b1812d1d597a4fa8472698e6df6ef716f5ce9"
		logic_hash = "4ff1f0912fb92e7ac5af49e1738dac897ff1f0a118d8ff905da45b0a91b3f4a7"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "dfdbd4dbfe16bcf779adb16352d5e57e3950e449e96c10bf33a91efee7c085e5"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { 8D 74 26 00 89 C2 83 ED 04 C1 E2 0B 31 C2 89 F0 C1 E8 13 89 D1 }

	condition:
		all of them
}