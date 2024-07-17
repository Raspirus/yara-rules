
rule ELASTIC_Windows_Generic_Threat_0A38C7D0 : FILE MEMORY
{
	meta:
		description = "Detects Windows Generic Threat (Windows.Generic.Threat)"
		author = "Elastic Security"
		id = "0a38c7d0-8f5e-4dcf-9aaf-5fcf96451d3c"
		date = "2024-01-22"
		modified = "2024-02-08"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Generic_Threat.yar#L2031-L2049"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "69ea7d2ea3ed6826ddcefb3c1daa63d8ab53dc6e66c59cf5c2506a8af1c62ef4"
		logic_hash = "e3fde76825772683c57f830759168fc9a3b3f3387f091828fd971e9ebba06d8a"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "43998ceb361ecf98d923c0388c00023f19d249a5ac0011dee0924fdff92af42b"
		severity = 50
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a1 = { 55 8B EC 8B 4D 08 85 C9 74 37 8B 45 0C 3D E0 10 00 00 7C 05 B8 E0 10 00 00 85 C0 7E 24 8D 50 FF B8 AB AA AA AA F7 E2 D1 EA 83 C1 02 42 53 8B FF 8A 41 FE 8A 19 88 59 FE 88 01 83 C1 03 4A 75 F0 }

	condition:
		all of them
}