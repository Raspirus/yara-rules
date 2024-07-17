rule ELASTIC_Windows_Trojan_Njrat_Eb2698D2 : FILE MEMORY
{
	meta:
		description = "Detects Windows Trojan Njrat (Windows.Trojan.Njrat)"
		author = "Elastic Security"
		id = "eb2698d2-c9fa-4b0b-900f-1c4c149cca4b"
		date = "2023-05-04"
		modified = "2023-06-13"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Trojan_Njrat.yar#L26-L44"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "d537397bc41f0a1cb964fa7be6658add5fe58d929ac91500fc7770c116d49608"
		logic_hash = "c32a641f2d639f56a8137b3e0d0be3261fba30084eeba9d1205974713413af9f"
		score = 75
		quality = 73
		tags = "FILE, MEMORY"
		fingerprint = "8eedcdabf459de87e895b142cd1a1b8c0e403ad8ec6466bc6ca493dd5daa823b"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a1 = { 24 65 66 65 39 65 61 64 63 2D 64 34 61 65 2D 34 62 39 65 2D 62 38 61 62 2D 37 65 34 37 66 38 64 62 36 61 63 39 }

	condition:
		all of them
}