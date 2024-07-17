
rule ELASTIC_Windows_Trojan_Bazar_De8D625A : FILE MEMORY
{
	meta:
		description = "Detects Windows Trojan Bazar (Windows.Trojan.Bazar)"
		author = "Elastic Security"
		id = "de8d625a-8f85-47b7-bcad-e3cc012e4654"
		date = "2022-01-14"
		modified = "2022-04-12"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Trojan_Bazar.yar#L61-L79"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "1ad9ac4785b82c8bfa355c7343b9afc7b1f163471c41671ea2f9152a1b550f0c"
		logic_hash = "5fd7bb4ac818ec1b4bfcb7d236868a31b2f726182407c07c7f06c1d7e9c15d02"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "17b2de5803589634fd7fb4643730fbebfa037c4d0b66be838a1c78af22da0228"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a = { 48 89 5C 24 08 48 89 74 24 10 57 48 83 EC 20 49 8B F0 48 8B FA 48 8B D9 48 85 D2 74 61 4D 85 C0 74 5C 48 39 11 75 06 4C 39 41 08 74 2B 48 8B 49 }

	condition:
		all of them
}