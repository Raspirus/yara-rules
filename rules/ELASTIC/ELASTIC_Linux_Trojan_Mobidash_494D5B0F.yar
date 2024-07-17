rule ELASTIC_Linux_Trojan_Mobidash_494D5B0F : FILE MEMORY
{
	meta:
		description = "Detects Linux Trojan Mobidash (Linux.Trojan.Mobidash)"
		author = "Elastic Security"
		id = "494d5b0f-09c7-4fcb-90e9-1efc57c45082"
		date = "2021-01-12"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Trojan_Mobidash.yar#L139-L157"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "7e08df5279f4d22f1f27553946b0dadd60bb8242d522a8dceb45ab7636433c2f"
		logic_hash = "6ddb94f9f44fe749a442592d491343a99bd870ea2d79596631d857516425e72b"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "e3316257592dc9654a5e63cf33c862ea1298af7a893e9175e1a15c7aaa595f6a"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { 00 18 00 00 00 40 04 00 00 01 5B 00 00 00 3A 00 00 00 54 04 00 00 05 A1 00 }

	condition:
		all of them
}