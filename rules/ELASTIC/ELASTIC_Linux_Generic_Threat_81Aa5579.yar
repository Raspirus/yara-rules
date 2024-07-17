rule ELASTIC_Linux_Generic_Threat_81Aa5579 : FILE MEMORY
{
	meta:
		description = "Detects Linux Generic Threat (Linux.Generic.Threat)"
		author = "Elastic Security"
		id = "81aa5579-6d94-42a7-9103-de3972dfe141"
		date = "2024-05-21"
		modified = "2024-06-12"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Generic_Threat.yar#L1026-L1044"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "6be0e2c98ba5255b76c31f689432a9de83a0d76a898c28dbed0ba11354fec6c2"
		logic_hash = "c94d590daf61217335a72f3e1bc24b09084cf0a5a174c013c5aa97c01707c2bc"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "60492dca0e33e2700c25502292e6ec54609b83c7616a96ae4731f4a1cd9e2f41"
		severity = 50
		arch_context = "x86, arm64"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a1 = { D0 4D E2 07 00 8D E8 03 10 A0 E3 0D 20 A0 E1 08 00 9F E5 84 00 00 EB 0C D0 8D E2 00 80 BD E8 66 00 90 00 01 C0 A0 E1 00 10 A0 E1 08 00 9F E5 02 30 A0 E1 0C 20 A0 E1 7B 00 00 EA 04 00 90 00 01 }

	condition:
		all of them
}