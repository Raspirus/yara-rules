
rule ELASTIC_Windows_Trojan_Amadey_7Abb059B : FILE MEMORY
{
	meta:
		description = "Detects Windows Trojan Amadey (Windows.Trojan.Amadey)"
		author = "Elastic Security"
		id = "7abb059b-4001-4eec-8185-1e0497e15062"
		date = "2021-06-28"
		modified = "2021-08-23"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Trojan_Amadey.yar#L1-L19"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "33e6b58ce9571ca7208d1c98610005acd439f3e37d2329dae8eb871a2c4c297e"
		logic_hash = "23b75d6df9e2a7f8e1efee46ecaf1fc84247312b19a8a1941ddbca1b2ce5e1db"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "686ae7cf62941d7db051fa8c45f0f7a27440fa0fdc5f0919c9667dfeca46ca1f"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a = { 18 83 78 14 10 72 02 8B 00 6A 01 6A 00 6A 00 6A 00 6A 00 56 }

	condition:
		all of them
}