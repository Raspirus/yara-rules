
rule ELASTIC_Windows_Trojan_Trickbot_52722678 : FILE MEMORY
{
	meta:
		description = "Detects Windows Trojan Trickbot (Windows.Trojan.Trickbot)"
		author = "Elastic Security"
		id = "52722678-afbe-43ec-a39b-6848b7d49488"
		date = "2021-03-28"
		modified = "2021-08-23"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Trojan_Trickbot.yar#L288-L305"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		logic_hash = "6340171fdde68b32de480f1f410aa4c491a8fffa7c1f699bf5fa72a12ecb77b8"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "e67dda5227be74424656957843777ea533b6800576fd85f978fd8fb50504209c"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a = { 2B 5D 0C 89 5D EC EB 03 8B 5D EC 8A 1C 3B 84 DB 74 0D 38 1F }

	condition:
		all of them
}