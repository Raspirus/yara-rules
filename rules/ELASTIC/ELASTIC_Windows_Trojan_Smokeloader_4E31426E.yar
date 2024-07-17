
rule ELASTIC_Windows_Trojan_Smokeloader_4E31426E : FILE MEMORY
{
	meta:
		description = "Detects Windows Trojan Smokeloader (Windows.Trojan.Smokeloader)"
		author = "Elastic Security"
		id = "4e31426e-d62e-4b6d-911b-4223e1f6adef"
		date = "2021-07-21"
		modified = "2021-08-23"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Trojan_Smokeloader.yar#L1-L19"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "1ce643981821b185b8ad73b798ab5c71c6c40e1f547b8e5b19afdaa4ca2a5174"
		logic_hash = "44ac7659964519ae72f83076bcd1b3e5244eb9cadd9a3b123dda78b0e9e07424"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "cf6d8615643198bc53527cb9581e217f8a39760c2e695980f808269ebe791277"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a = { 5B 81 EB 34 10 00 00 6A 30 58 64 8B 00 8B 40 0C 8B 40 1C 8B 40 08 89 85 C0 }

	condition:
		all of them
}