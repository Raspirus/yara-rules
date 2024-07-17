
rule ELASTIC_Windows_Generic_Threat_C34E19E9 : FILE MEMORY
{
	meta:
		description = "Detects Windows Generic Threat (Windows.Generic.Threat)"
		author = "Elastic Security"
		id = "c34e19e9-c666-4fc5-bbb3-75f64d247899"
		date = "2024-03-04"
		modified = "2024-06-12"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Generic_Threat.yar#L3003-L3021"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "f9048348a59d9f824b45b16b1fdba9bfeda513aa9fbe671442f84b81679232db"
		logic_hash = "87999b6f2cf359b6436ee7e57691ac73fc41f3947bf8fef3f6b98148e17f180d"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "148ffb1f73a3f337d188c78de638880ea595a812dfa7a0ada6dc66805637aeb3"
		severity = 50
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a1 = { 28 00 00 0A 73 18 00 00 0A 7E 02 00 00 04 17 8D 3A 00 00 01 25 16 1F 2C 9D 6F 28 00 00 0A 8E 69 6F 29 00 00 0A 9A 0A 7E 01 00 00 04 17 8D 3A 00 00 01 25 16 1F 2C 9D 6F 28 00 00 0A 73 18 00 00 }

	condition:
		all of them
}