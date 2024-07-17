
rule ELASTIC_Windows_Generic_Threat_55D6A1Ab : FILE MEMORY
{
	meta:
		description = "Detects Windows Generic Threat (Windows.Generic.Threat)"
		author = "Elastic Security"
		id = "55d6a1ab-2041-44a5-ae0e-23671fa2b001"
		date = "2024-01-07"
		modified = "2024-01-12"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Generic_Threat.yar#L712-L731"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "1ca6ed610479b5aaaf193a2afed8f2ca1e32c0c5550a195d88f689caab60c6fb"
		logic_hash = "4f3a0b2e45ae4e6a00f137798b700a0925fa6eb19ea6b871d7eeb565548888ba"
		score = 75
		quality = 71
		tags = "FILE, MEMORY"
		fingerprint = "cd81b61929b18d59630814718443c4b158f9dcc89c7d03a46a531ffc5843f585"
		severity = 50
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a1 = { 51 51 31 33 37 32 33 39 32 34 38 20 }
		$a2 = { 74 65 6E 63 65 6E 74 3A 2F 2F 6D 65 73 73 61 67 65 2F 3F 75 69 6E 3D 31 33 37 32 33 39 32 34 38 26 53 69 74 65 3D 63 66 }

	condition:
		all of them
}