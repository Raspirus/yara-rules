rule ELASTIC_Linux_Trojan_Gafgyt_4D81Ad42 : FILE MEMORY
{
	meta:
		description = "Detects Linux Trojan Gafgyt (Linux.Trojan.Gafgyt)"
		author = "Elastic Security"
		id = "4d81ad42-bf08-48a9-9a93-85cb491257b3"
		date = "2021-04-06"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Trojan_Gafgyt.yar#L1187-L1205"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "3021a861e6f03df3e7e3919e6255bdae6e48163b9a8ba4f1a5c5dced3e3e368b"
		logic_hash = "57b54eed37690949ba2d4eff713691f16f00207d7b374beb7dfa2e368588dbb0"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "f285683c3b145990e1b6d31d3c9d09177ebf76f183d0fa336e8df3dbcba24366"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { 0F 44 C8 07 0B BF F1 1B 7E 83 CD FF 31 DB 2E 22 }

	condition:
		all of them
}