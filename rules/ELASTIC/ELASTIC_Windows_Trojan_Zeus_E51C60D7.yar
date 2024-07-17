
rule ELASTIC_Windows_Trojan_Zeus_E51C60D7 : FILE MEMORY
{
	meta:
		description = "Detects strings used in Zeus web injects. Many other malware families are built on Zeus and may hit on this signature."
		author = "Elastic Security"
		id = "e51c60d7-3afa-4cf5-91d8-7782e5026e46"
		date = "2021-02-07"
		modified = "2021-10-04"
		reference = "https://www.virusbulletin.com/virusbulletin/2014/10/paper-evolution-webinjects"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Trojan_Zeus.yar#L1-L25"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "d7e9cb60674e0a05ad17eb96f8796d9f23844a33f83aba5e207b81979d0f2bf3"
		logic_hash = "cde738f95dbad1fbad59e20528b2f577e5e3ee5fcb37c68a45d53c689d2af525"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "813e2ee2447fcffdde6519dc6c52369a5d06c668b76c63bb8b65809805ecefba"
		threat_name = "Windows.Trojan.Zeus"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a1 = "name=%s&port=%u" ascii fullword
		$a2 = "data_inject" ascii wide fullword
		$a3 = "keylog.txt" ascii fullword
		$a4 = "User-agent: %s]]]" ascii fullword
		$a5 = "%s\\%02d.bmp" ascii fullword

	condition:
		all of them
}