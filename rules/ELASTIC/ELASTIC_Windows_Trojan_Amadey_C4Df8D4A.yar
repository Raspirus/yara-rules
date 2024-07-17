
rule ELASTIC_Windows_Trojan_Amadey_C4Df8D4A : FILE MEMORY
{
	meta:
		description = "Detects Windows Trojan Amadey (Windows.Trojan.Amadey)"
		author = "Elastic Security"
		id = "c4df8d4a-01f4-466f-8225-7c7f462b29e7"
		date = "2021-06-28"
		modified = "2021-08-23"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Trojan_Amadey.yar#L21-L39"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "9039d31d0bd88d0c15ee9074a84f8d14e13f5447439ba80dd759bf937ed20bf2"
		logic_hash = "7f96c4de585223033fb7e7906be6d6898651ecf30be51ed01abde18ef52c0e1e"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "4623c591ea465e23f041db77dc68ddfd45034a8bde0f20fd5fbcec060851200c"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a1 = "D:\\Mktmp\\NL1\\Release\\NL1.pdb" fullword

	condition:
		all of them
}