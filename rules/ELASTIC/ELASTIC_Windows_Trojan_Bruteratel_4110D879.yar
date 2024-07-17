rule ELASTIC_Windows_Trojan_Bruteratel_4110D879 : FILE MEMORY
{
	meta:
		description = "Detects Windows Trojan Bruteratel (Windows.Trojan.BruteRatel)"
		author = "Elastic Security"
		id = "4110d879-8d36-4004-858d-e62400948920"
		date = "2023-05-10"
		modified = "2023-06-13"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Trojan_BruteRatel.yar#L111-L130"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "e0fbbc548fdb9da83a72ddc1040463e37ab6b8b544bf0d2b206bfff352175afe"
		logic_hash = "22c27523ddd8183c41da40f7ff908ae5bdee3b482c8a3f70aaa63a4c419e515b"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "64d7a121961108d17e03fa767bd5bc194c8654dfa18b3b2f38cf6c95a711f794"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a1 = { 04 01 75 E2 48 83 C0 01 44 0F B6 04 02 45 84 C0 75 EC 48 89 }
		$a2 = { C8 48 83 E9 20 44 0F B6 40 E0 41 80 F8 E9 74 0B 44 0F B6 49 03 41 80 }

	condition:
		all of them
}