
rule ELASTIC_Windows_Trojan_Qbot_D91C1384 : FILE MEMORY
{
	meta:
		description = "Detects Windows Trojan Qbot (Windows.Trojan.Qbot)"
		author = "Elastic Security"
		id = "d91c1384-839f-4062-8a8d-5cda931029ae"
		date = "2021-07-08"
		modified = "2021-08-23"
		reference = "https://www.elastic.co/security-labs/exploring-the-qbot-attack-pattern"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Trojan_Qbot.yar#L1-L20"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "18ac3870aaa9aaaf6f4a5c0118daa4b43ad93d71c38bf42cb600db3d786c6dda"
		logic_hash = "8fd8249a2af236c92ccbc20b2a8380f69ca75976bd64bad167828e9ab4c6ed90"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "1b47ede902b6abfd356236e91ed3e741cf1744c68b6bb566f0d346ea07fee49a"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a = { FE 8A 14 06 88 50 FF 8A 54 BC 11 88 10 8A 54 BC 10 88 50 01 47 83 }

	condition:
		all of them
}