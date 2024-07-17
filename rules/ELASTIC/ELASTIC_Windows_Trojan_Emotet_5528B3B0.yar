rule ELASTIC_Windows_Trojan_Emotet_5528B3B0 : FILE MEMORY
{
	meta:
		description = "Detects Windows Trojan Emotet (Windows.Trojan.Emotet)"
		author = "Elastic Security"
		id = "5528b3b0-d4cb-485e-bc0c-96415ec3a795"
		date = "2021-11-17"
		modified = "2022-01-13"
		reference = "https://www.elastic.co/security-labs/emotet-dynamic-configuration-extraction"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Trojan_Emotet.yar#L22-L41"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "eeb13cd51faa7c23d9a40241d03beb239626fbf3efe1dbbfa3994fc10dea0827"
		logic_hash = "bb784ab0e064bafa8450b6bb15ef534af38254ea3c096807571c2c27f7cdfd76"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "717ed656d1bd4ba0e4dae8e47268e2c068dad3e3e883ff6da2f951d61f1be642"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a = { 20 89 44 24 10 83 C2 02 01 74 24 10 01 7C 24 10 29 5C 24 10 66 }

	condition:
		all of them
}