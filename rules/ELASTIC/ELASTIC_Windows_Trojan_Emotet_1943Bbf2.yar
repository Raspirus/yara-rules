rule ELASTIC_Windows_Trojan_Emotet_1943Bbf2 : FILE MEMORY
{
	meta:
		description = "Detects Windows Trojan Emotet (Windows.Trojan.Emotet)"
		author = "Elastic Security"
		id = "1943bbf2-56c0-443e-9208-cd8fc3b02d79"
		date = "2021-11-18"
		modified = "2022-01-13"
		reference = "https://www.elastic.co/security-labs/emotet-dynamic-configuration-extraction"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Trojan_Emotet.yar#L43-L62"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "5abec3cd6aa066b1ddc0149a911645049ea1da66b656c563f9a384e821c5db38"
		logic_hash = "41838e335b9314b8759922f23ec8709f46e6a26633f3685ac98ada5828191d35"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "df8b73d83a50a58ed8332b7580c970c2994aa31d2ac1756cff8e0cd1777fb8fa"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a = { 66 83 38 5C 74 0A 83 C0 02 66 39 30 75 F2 EB 06 33 C9 66 89 }

	condition:
		all of them
}