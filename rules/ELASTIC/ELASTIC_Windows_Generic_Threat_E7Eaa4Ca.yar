rule ELASTIC_Windows_Generic_Threat_E7Eaa4Ca : FILE MEMORY
{
	meta:
		description = "Detects Windows Generic Threat (Windows.Generic.Threat)"
		author = "Elastic Security"
		id = "e7eaa4ca-45ee-42ea-9604-d9d569eed0aa"
		date = "2024-01-04"
		modified = "2024-01-12"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Generic_Threat.yar#L570-L587"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		logic_hash = "600da0c88dc0606e05f60ecd3b9a90469eef8ac7a702ef800c833f7fd17eb13e"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "ede23e801a67bc43178eea87a83eb0ef32a74d48476a8273a25a7732af6f22a6"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a = { C8 F7 C6 A8 13 F7 01 E9 2C 99 08 00 4C 03 D1 E9 }

	condition:
		all of them
}