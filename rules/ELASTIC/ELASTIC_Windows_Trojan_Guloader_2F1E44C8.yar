
rule ELASTIC_Windows_Trojan_Guloader_2F1E44C8 : FILE MEMORY
{
	meta:
		description = "Detects Windows Trojan Guloader (Windows.Trojan.Guloader)"
		author = "Elastic Security"
		id = "2f1e44c8-f269-4cd6-a516-8d9282ddcfbc"
		date = "2023-10-30"
		modified = "2023-11-02"
		reference = "https://www.elastic.co/security-labs/getting-gooey-with-guloader-downloader"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Trojan_Guloader.yar#L47-L70"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "6ae7089aa6beaa09b1c3aa3ecf28a884d8ca84f780aab39902223721493b1f99"
		logic_hash = "434b33c3fdc6bf4b0f59cd4aba66327d0b7ab524be603b256494d46b609cecd5"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "b00255f8d7ce460ffc778e96f6101db753e8992d36ee75a25b48e32ac7817c58"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$djb2_str_compare = { 83 C0 08 83 3C 04 00 0F 84 [4] 39 14 04 75 }
		$check_exception = { 8B 45 ?? 8B 00 38 EC 8B 58 ?? 84 FD 81 38 05 00 00 C0 }
		$parse_mem = { 18 00 10 00 00 83 C0 18 50 83 E8 04 81 00 00 10 00 00 50 }
		$hw_bp = { 39 48 0C 0F 85 [4] 39 48 10 0F 85 [4] 39 48 14 0F 85 [7] 39 48 18 }
		$scan_protection = { 39 ?? 14 8B [5] 0F 84 }

	condition:
		2 of them
}