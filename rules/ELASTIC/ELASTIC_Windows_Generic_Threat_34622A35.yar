rule ELASTIC_Windows_Generic_Threat_34622A35 : FILE MEMORY
{
	meta:
		description = "Detects Windows Generic Threat (Windows.Generic.Threat)"
		author = "Elastic Security"
		id = "34622a35-9ddf-4091-8b0c-c9430ecea57c"
		date = "2024-01-01"
		modified = "2024-01-12"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Generic_Threat.yar#L363-L381"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "c021c6adca0ddf38563a13066a652e4d97726175983854674b8dae2f6e59c83f"
		logic_hash = "2b49bd5d3a18307a46f44d9dfeea858ddaa6084f86f96b83b874cee7603e1c11"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "427762237cd1040bad58e9d9f7ad36c09134d899c5105e977f94933827c5d5e0"
		severity = 50
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a1 = { 55 8B EC 81 EC 88 00 00 00 C7 45 FC 00 00 00 00 C7 45 F8 00 00 00 00 68 4C 00 00 00 E8 A3 42 00 00 83 C4 04 89 45 F4 8B D8 8B F8 33 C0 B9 13 00 00 00 F3 AB 83 C3 38 53 68 10 00 00 00 E8 82 42 }

	condition:
		all of them
}