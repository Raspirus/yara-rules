
rule ELASTIC_Windows_Trojan_Bloodalchemy_E510798D : FILE MEMORY
{
	meta:
		description = "Detects Windows Trojan Bloodalchemy (Windows.Trojan.BloodAlchemy)"
		author = "Elastic Security"
		id = "e510798d-a938-47ba-92e3-0c1bcd3ce9a9"
		date = "2023-09-25"
		modified = "2023-09-25"
		reference = "https://www.elastic.co/security-labs/disclosing-the-bloodalchemy-backdoor"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Trojan_BloodAlchemy.yar#L22-L41"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		logic_hash = "7919bb5f19745a1620e6be91622c40083cbd2ddb02905215736a2ed11e9af5c4"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "151519156e4c6b5395c03f70c77601681f17f86a08db96a622b9489a3df682d6"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a1 = { 55 8B EC 83 EC 54 53 8B 5D 08 56 57 33 FF 89 55 F4 89 4D F0 BE 00 00 00 02 89 7D F8 89 7D FC 85 DB }
		$a2 = { 55 8B EC 83 EC 0C 56 57 33 C0 8D 7D F4 AB 8D 4D F4 AB AB E8 42 10 00 00 8B 7D F4 33 F6 85 FF 74 03 8B 77 08 }

	condition:
		any of them
}