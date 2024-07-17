
rule ELASTIC_Windows_Generic_Threat_2Bb7Fbe3 : FILE MEMORY
{
	meta:
		description = "Detects Windows Generic Threat (Windows.Generic.Threat)"
		author = "Elastic Security"
		id = "2bb7fbe3-2add-4ae9-adbf-5f043475d879"
		date = "2023-12-18"
		modified = "2024-01-12"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Generic_Threat.yar#L102-L120"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "65cc8704c0e431589d196eadb0ac8a19151631c8d4ab7375d7cb18f7b763ba7b"
		logic_hash = "36e1ab766e09e8d06b9179f67a1cb842ba257f140610964a941fb462ed3e803c"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "e20c20c61768bd936cc18df56d7ec12d92745b6534ac8149bf367d6ad62fa8bd"
		severity = 50
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a1 = { 83 EC 14 68 B6 32 40 00 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 83 EC 30 53 56 57 89 65 EC C7 45 F0 C0 15 40 00 33 F6 89 75 F4 89 75 F8 89 75 E0 89 75 DC 89 75 D8 6A 01 FF 15 AC 10 }

	condition:
		all of them
}