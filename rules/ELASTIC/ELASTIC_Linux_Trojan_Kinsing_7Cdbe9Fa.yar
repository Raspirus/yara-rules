rule ELASTIC_Linux_Trojan_Kinsing_7Cdbe9Fa : FILE MEMORY
{
	meta:
		description = "Detects Linux Trojan Kinsing (Linux.Trojan.Kinsing)"
		author = "Elastic Security"
		id = "7cdbe9fa-39a3-43a0-853a-16f41e20f304"
		date = "2021-12-13"
		modified = "2022-01-26"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Trojan_Kinsing.yar#L20-L38"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "b3527e3d03a30fcf1fdaa73a1b3743866da6db088fbfa5f51964f519e22d05e6"
		logic_hash = "c6f5d2cf0430301ec0eae57808100203b69428f258e0e6882fecbc762d73f4bf"
		score = 75
		quality = 73
		tags = "FILE, MEMORY"
		fingerprint = "2452c2821b4ca104a18d3733ee8f6744a738aca197aa35392c480e224a5f8175"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { 73 2E 72 75 22 20 7C 20 61 77 6B 20 27 7B 70 72 69 6E 74 20 }

	condition:
		all of them
}