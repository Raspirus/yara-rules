rule ELASTIC_Windows_Generic_Threat_803Feff4 : FILE MEMORY
{
	meta:
		description = "Detects Windows Generic Threat (Windows.Generic.Threat)"
		author = "Elastic Security"
		id = "803feff4-e4c2-4d8c-b736-47bb10fd5ce8"
		date = "2024-01-17"
		modified = "2024-02-08"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Generic_Threat.yar#L1464-L1482"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "8f150dfb13e4a2ff36231f873e4c0677b5db4aa235d8f0aeb41e02f7e31c1e05"
		logic_hash = "e22b8b208ff104e2843d897c425467f2f0ec0c586c4db578da90aeaef0209e1d"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "3bbb00aa18086ac804f6ddf99a50821744a420f46b6361841b8bcd2872e597f1"
		severity = 50
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a1 = { 6F 01 00 06 6F 25 00 00 0A 02 7B 03 00 00 04 73 8D 01 00 06 6F 25 00 00 0A 02 7B 03 00 00 04 73 92 01 00 06 6F 25 00 00 0A 02 7B 03 00 00 04 73 9A 01 00 06 6F 25 00 00 0A 02 7B 03 00 00 04 73 }

	condition:
		all of them
}