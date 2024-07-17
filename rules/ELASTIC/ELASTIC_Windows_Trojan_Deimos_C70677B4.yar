
rule ELASTIC_Windows_Trojan_Deimos_C70677B4 : FILE MEMORY
{
	meta:
		description = "Detects Windows Trojan Deimos (Windows.Trojan.Deimos)"
		author = "Elastic Security"
		id = "c70677b4-f5ba-440b-ba31-31e80caee2fe"
		date = "2021-09-18"
		modified = "2022-01-13"
		reference = "https://www.elastic.co/security-labs/going-coast-to-coast-climbing-the-pyramid-with-the-deimos-implant"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Trojan_Deimos.yar#L24-L44"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "2c1941847f660a99bbc6de16b00e563f70d900f9dbc40c6734871993961d3d3e"
		logic_hash = "c969221f025b114b9d5738d43b6021ab9481dbc6b35eb129ea4f806160b1adc3"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "ffe0dec3585da9cbb9f8a0fac1bb6fd43d5d6e20a6175aaa889ae13ef2ed101f"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a1 = { 00 57 00 58 00 59 00 5A 00 5F 00 00 17 75 00 73 00 65 00 72 00 }
		$a2 = { 0C 08 16 1F 68 9D 08 17 1F 77 9D 08 18 1F 69 9D 08 19 1F 64 9D }

	condition:
		1 of ($a*)
}