
rule ELASTIC_Windows_Trojan_Microbackdoor_903E33C3 : FILE MEMORY
{
	meta:
		description = "Detects Windows Trojan Microbackdoor (Windows.Trojan.MicroBackdoor)"
		author = "Elastic Security"
		id = "903e33c3-d8f1-4c3b-900b-7503edb11951"
		date = "2022-03-07"
		modified = "2022-04-12"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Trojan_MicroBackdoor.yar#L1-L19"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "fbbfcc81a976b57739ef13c1545ea4409a1c69720469c05ba249a42d532f9c21"
		logic_hash = "5f96f68df442eb1da21d87c3ae954c4e36cf87db583cbef1775f8ca9e76b776e"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "06b3c0164c2d06f50d1e6ae0a9edf823ae1fef53574e0d20020aada8721dfee0"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a = { 55 8B EC 83 EC 1C 56 57 E8 33 01 00 00 8B F8 85 FF 74 48 BA 26 80 AC C8 8B CF E8 E1 01 00 00 BA }

	condition:
		all of them
}