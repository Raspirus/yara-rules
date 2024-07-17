
rule ELASTIC_Windows_Generic_Threat_61315534 : FILE MEMORY
{
	meta:
		description = "Detects Windows Generic Threat (Windows.Generic.Threat)"
		author = "Elastic Security"
		id = "61315534-9d80-428b-bc56-ff4836ab0c4a"
		date = "2024-01-11"
		modified = "2024-02-08"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Generic_Threat.yar#L974-L992"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "819447ca71080f083b1061ed6e333bd9ef816abd5b0dd0b5e6a58511ab1ce8b9"
		logic_hash = "0fdfe3bb6ebdaac4324a45dac8680f00684d0030419f26f3f72ed002bf5a2a34"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "e5cff64bc04b271237015154ddeb275453536ffa8cbce60389b6ed37e6478788"
		severity = 50
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a1 = { 55 8B EC 51 51 8A 4D 08 F6 C1 01 74 0A DB 2D B0 D7 41 00 DB 5D 08 9B F6 C1 08 74 10 9B DF E0 DB 2D B0 D7 41 00 DD 5D F8 9B 9B DF E0 F6 C1 10 74 0A DB 2D BC D7 41 00 DD 5D F8 9B F6 C1 04 74 09 }

	condition:
		all of them
}