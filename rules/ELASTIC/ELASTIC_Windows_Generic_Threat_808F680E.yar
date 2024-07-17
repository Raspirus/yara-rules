
rule ELASTIC_Windows_Generic_Threat_808F680E : FILE MEMORY
{
	meta:
		description = "Detects Windows Generic Threat (Windows.Generic.Threat)"
		author = "Elastic Security"
		id = "808f680e-db35-488f-b942-79213890b336"
		date = "2024-01-10"
		modified = "2024-01-12"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Generic_Threat.yar#L894-L912"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "df6955522532e365239b94e9d834ff5eeeb354eec3e3672c48be88725849ac1c"
		logic_hash = "22d91a87c01b401d4a203fbabb93a9b45fd6d8819125c56d9c427449b06d2f84"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "4b4b3b244d0168b11a8df4805f9043c6e4039ced332a7ba9c9d0d962ad6f6a0e"
		severity = 50
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a1 = { 28 00 00 0A 20 00 00 00 00 FE 01 2A 13 30 02 00 6C 00 00 00 01 00 00 11 20 00 00 00 00 FE 0E 00 00 38 54 00 00 00 00 FE 0C 00 00 20 01 00 00 00 FE 01 39 12 00 00 00 FE 09 01 00 FE 09 02 00 51 }

	condition:
		all of them
}