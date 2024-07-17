rule ELASTIC_Windows_Trojan_Emotet_18379A8D : FILE MEMORY
{
	meta:
		description = "Detects Windows Trojan Emotet (Windows.Trojan.Emotet)"
		author = "Elastic Security"
		id = "18379a8d-f1f2-49cc-8edf-58a3ba77efe7"
		date = "2021-11-17"
		modified = "2022-01-13"
		reference = "https://www.elastic.co/security-labs/emotet-dynamic-configuration-extraction"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Trojan_Emotet.yar#L1-L20"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "eeb13cd51faa7c23d9a40241d03beb239626fbf3efe1dbbfa3994fc10dea0827"
		logic_hash = "2ad72ce2a352b91a4fa597ee9e796035298cfcee6fdc13dd3f64579d8da96b97"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "b7650b902a1a02029e28c88dd7ff91d841136005b0246ef4a08aaf70e57df9cc"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a = { 04 33 CB 88 0A 8B C1 C1 E8 08 8D 52 04 C1 E9 10 88 42 FD 88 }

	condition:
		all of them
}