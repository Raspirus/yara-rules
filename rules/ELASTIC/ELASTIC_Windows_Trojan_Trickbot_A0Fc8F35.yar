rule ELASTIC_Windows_Trojan_Trickbot_A0Fc8F35 : FILE MEMORY
{
	meta:
		description = "Detects Windows Trojan Trickbot (Windows.Trojan.Trickbot)"
		author = "Elastic Security"
		id = "a0fc8f35-cbeb-43a8-b00d-7a0f981e84e4"
		date = "2021-03-28"
		modified = "2021-08-23"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Trojan_Trickbot.yar#L174-L191"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		logic_hash = "7ab2b45ddfc1d7fa409a6ea3dfd8d4940e1bdf3fc0cb6c7e8d49c60e7bda5b1b"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "033ff4f47fece45dfa7e3ba185df84a767691e56f0081f4ed96f9e2455a563cb"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a = { 18 33 DB 53 6A 01 53 53 8D 4C 24 34 51 8B F0 89 5C 24 38 FF D7 }

	condition:
		all of them
}