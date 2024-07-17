rule ELASTIC_Windows_Trojan_Bloodalchemy_3793364E : FILE MEMORY
{
	meta:
		description = "Detects Windows Trojan Bloodalchemy (Windows.Trojan.BloodAlchemy)"
		author = "Elastic Security"
		id = "3793364e-a73c-4cf0-855c-fdcdb2b88386"
		date = "2023-09-25"
		modified = "2023-09-25"
		reference = "https://www.elastic.co/security-labs/disclosing-the-bloodalchemy-backdoor"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Trojan_BloodAlchemy.yar#L1-L20"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		logic_hash = "c9f03767b92bb2c44f6b386e1f0a521f1a7a063cf73799844cc3423d4a7de7be"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "b4620f360093284ae6f2296b4239227099f58f8f0cfe9f70298c84d6cbe7fa29"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a1 = { 55 8B EC 51 83 65 FC 00 53 56 57 BF 00 20 00 00 57 6A 40 FF 15 }
		$a2 = { 55 8B EC 81 EC 80 00 00 00 53 56 57 33 FF 8D 45 80 6A 64 57 50 89 7D E4 89 7D EC 89 7D F0 89 7D }

	condition:
		all of them
}