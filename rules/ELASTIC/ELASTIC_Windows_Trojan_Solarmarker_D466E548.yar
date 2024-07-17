rule ELASTIC_Windows_Trojan_Solarmarker_D466E548 : FILE MEMORY
{
	meta:
		description = "Detects Windows Trojan Solarmarker (Windows.Trojan.SolarMarker)"
		author = "Elastic Security"
		id = "d466e548-eb88-41e6-9740-ae59980db835"
		date = "2023-12-12"
		modified = "2024-01-12"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Trojan_SolarMarker.yar#L1-L20"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "330f5067c93041821be4e7097cf32fb569e2e1d00e952156c9aafcddb847b873"
		hash = "e2a620e76352fa7ac58407a711821da52093d97d12293ae93d813163c58eb84b"
		logic_hash = "c0792bc3c1a2f01ff4b8d0a12c95a74491c2805c876f95a26bbeaabecdff70e9"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "0f4b0162ee8283959e10c459ddc55eb00eae30d241119aad1aa3ea6c101f9889"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a1 = { 00 00 2B 03 00 2B 15 00 07 2D 09 08 16 FE 01 16 FE 01 2B 01 17 00 13 04 11 04 2D 8C 07 2D 06 08 }

	condition:
		all of them
}