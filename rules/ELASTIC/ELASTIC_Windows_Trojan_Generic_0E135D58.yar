rule ELASTIC_Windows_Trojan_Generic_0E135D58 : FILE MEMORY
{
	meta:
		description = "Detects Windows Trojan Generic (Windows.Trojan.Generic)"
		author = "Elastic Security"
		id = "0e135d58-efd9-4d5e-95d8-ddd597f8e6a8"
		date = "2024-03-19"
		modified = "2024-03-19"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Trojan_Generic.yar#L312-L330"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "a91c1d3965f11509d1c1125210166b824a79650f29ea203983fffb5f8900858c"
		logic_hash = "bc10218b1d761f72836bb5f9bb41d3f0fe13c4baa1109025269f938ec642aec4"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "e1a9e0c4e5531ae4dd2962285789c3bb8bb2621aa20437384fc3abcc349718c6"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a = { 55 8B EC 8B 45 14 56 57 8B 7D 08 33 F6 89 47 0C 39 75 10 76 15 8B }

	condition:
		1 of them
}