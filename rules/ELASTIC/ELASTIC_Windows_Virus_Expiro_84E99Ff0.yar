rule ELASTIC_Windows_Virus_Expiro_84E99Ff0 : FILE MEMORY
{
	meta:
		description = "Detects Windows Virus Expiro (Windows.Virus.Expiro)"
		author = "Elastic Security"
		id = "84e99ff0-bff3-4a9c-93fb-504a32cbc44d"
		date = "2023-09-26"
		modified = "2023-11-02"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Virus_Expiro.yar#L1-L20"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "47107836ead700bddbe9e8a0c016b5b1443c785442b2addbb50a70445779bad7"
		logic_hash = "ce4847bf5850c1f30dca9603bfbbfbb69339285f096ac469c6d2d4b04f5562b4"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "843182cbbf7ff65699001f074972d584c65bdb1e1d76210b44cf6ba06830253c"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a1 = { 50 51 52 53 55 56 57 E8 00 00 00 00 5B 81 EB ?? ?? ?? 00 BA 00 00 00 00 53 81 }
		$a2 = { 81 C2 00 04 00 00 81 C3 00 04 00 00 }

	condition:
		all of them
}