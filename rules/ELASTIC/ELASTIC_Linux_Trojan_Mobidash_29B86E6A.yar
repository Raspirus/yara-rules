
rule ELASTIC_Linux_Trojan_Mobidash_29B86E6A : FILE MEMORY
{
	meta:
		description = "Detects Linux Trojan Mobidash (Linux.Trojan.Mobidash)"
		author = "Elastic Security"
		id = "29b86e6a-fcad-49ac-ae78-ce28987f7363"
		date = "2021-01-12"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Trojan_Mobidash.yar#L198-L215"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		logic_hash = "dd5f44249cc4c91f39a0e7d0b236ebeed8f78d5fcb03c7ebc80ef1c738b18336"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "5d7d930f39e435fc22921571fe96db912eed79ec630d4ed60da6f007073b7362"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { 2E 10 73 2E 10 02 47 2E 10 56 2E 10 5C 2E 10 4E 2E 10 49 2E 10 }

	condition:
		all of them
}