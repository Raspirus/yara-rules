rule ELASTIC_Windows_Trojan_Matanbuchus_4Ce9Affb : FILE MEMORY
{
	meta:
		description = "Detects Windows Trojan Matanbuchus (Windows.Trojan.Matanbuchus)"
		author = "Elastic Security"
		id = "4ce9affb-58ef-4d31-b1ff-5a1c52822a01"
		date = "2022-03-17"
		modified = "2022-04-12"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Trojan_Matanbuchus.yar#L24-L42"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "4eb85a5532b98cbc4a6db1697cf46b9e2b7e28e89d6bbfc137b36c0736cd80e2"
		logic_hash = "16441eb4617b6b3cb1e7d600959a5cbfe15c72c00361b45551b7ef4c81f78462"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "61d32df2ea730343ab497f50d250712e89ec942733c8cc4421083a3823ab9435"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a1 = { F4 83 7D F4 00 77 43 72 06 83 7D F0 11 73 3B 6A 00 6A 01 8B }

	condition:
		all of them
}