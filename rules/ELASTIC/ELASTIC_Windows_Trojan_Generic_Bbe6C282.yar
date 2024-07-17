rule ELASTIC_Windows_Trojan_Generic_Bbe6C282 : FILE MEMORY
{
	meta:
		description = "Detects Windows Trojan Generic (Windows.Trojan.Generic)"
		author = "Elastic Security"
		id = "bbe6c282-e92d-4021-bdaf-189337e4abf0"
		date = "2022-03-02"
		modified = "2022-04-12"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Trojan_Generic.yar#L91-L109"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "a44c46d4b9cf1254aaabd1e689f84c4d2c3dd213597f827acabface03a1ae6d1"
		logic_hash = "fe874d69ae71775cf997845c90e731479569e2ac1ac882a4b8c3c73d015b1f30"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "e004d77440a86c23f23086e1ada6d1453178b9c2292782c1c88a7b14151c10fe"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a1 = { 00 D1 1C A5 03 08 08 00 8A 5C 01 08 08 00 8A 58 01 2E 54 FF }

	condition:
		all of them
}