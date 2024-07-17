
rule ELASTIC_Windows_Generic_Threat_83C38E63 : FILE MEMORY
{
	meta:
		description = "Detects Windows Generic Threat (Windows.Generic.Threat)"
		author = "Elastic Security"
		id = "83c38e63-6a18-4def-abf2-35e36210e4cf"
		date = "2024-01-12"
		modified = "2024-02-08"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Generic_Threat.yar#L1179-L1198"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "2121a0e5debcfeedf200d7473030062bc9f5fbd5edfdcd464dfedde272ff1ae7"
		logic_hash = "89d4036290a29b372918205bba85698d6343109503766cbb13999b5177fc3152"
		score = 75
		quality = 71
		tags = "FILE, MEMORY"
		fingerprint = "9cc8ee8dfa6080a18575a494e0b424154caecedcc8c8fd07dd3c91956c146d1e"
		severity = 50
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a1 = { 32 65 65 64 36 35 36 64 64 35 38 65 39 35 30 35 62 34 33 39 35 34 32 30 31 39 36 66 62 33 35 36 }
		$a2 = { 34 2A 34 4A 34 52 34 60 34 6F 34 7C 34 }

	condition:
		all of them
}