
rule ELASTIC_Windows_Trojan_Sourshark_Adee8A17 : FILE MEMORY
{
	meta:
		description = "Detects Windows Trojan Sourshark (Windows.Trojan.SourShark)"
		author = "Elastic Security"
		id = "adee8a17-cc0c-40b8-9ee6-a01b41e9befd"
		date = "2024-06-04"
		modified = "2024-06-12"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Trojan_SourShark.yar#L23-L41"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "07eb88c69437ee6e3ea2fbab5f2fbd8e846125d18c1da7d72bb462e9d083c9fc"
		logic_hash = "98a4d31849a1828c2154b5032a81580f5dcc8d4a65b96dea3a727e2a82a51666"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "f35ebe8a220693ef6288efae0d325c3f40e70836c088599cb9b620c59fab09da"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a = { 8B 45 08 8B 4C BE 08 8A 04 02 02 C3 02 C1 0F B6 D8 8B 44 9E 08 89 44 BE 08 8D 42 01 33 D2 89 4C 9E 08 47 83 F8 20 0F 4C D0 81 FF 00 01 00 00 7C CF 8B 16 33 FF 8B 5E 04 39 7D FC 7E 33 0F 1F 00 }

	condition:
		all of them
}